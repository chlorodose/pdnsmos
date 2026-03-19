setLocal("0.0.0.0:53")
addLocal("[::]:53")
setACL({ "0.0.0.0/0", "::/0" })
webserver("0.0.0.0:10050")
controlSocket("127.0.0.1:5199")
setKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
setWebserverConfig({
	password = "mypasswd",
	acl = "0.0.0.0/0",
})

newServer({ address = "1.1.1.1:53", name = "cloudflare", pool = "default", healthCheckMode = "lazy" })
newServer({ address = "223.5.5.5:53", name = "alidns", pool = "cn", healthCheckMode = "lazy" })
newServer({ address = "8.8.8.8:53", name = "google", pool = "un", healthCheckMode = "lazy" })
newServer({
	address = "8.8.8.8:53",
	-- address = "223.5.5.5:53",
	name = "google_cn",
	-- useClientSubnet = true, -- How to send custom ECS?
	pool = "uncn",
	healthCheckMode = "lazy",
})

local cache = newPacketCache(
	65536,
	{ maxTTL = 86400, minTTL = 0, temporaryFailureTTL = 60, staleTTL = 60, dontAge = false, shuffle = false }
)
getPool("default"):setCache(cache)
getPool("cn"):setCache(cache)
getPool("un"):setCache(cache)
getPool("uncn"):setCache(cache)

local pdnsmos = require("pdnsmos")

-- addAction(AllRule(), LogAction(""))
-- addResponseAction(AllRule(), LogResponseAction(""))

local TrivalQuery = function()
	return AndRule({
		RDRule(),
		OrRule({ QTypeRule(DNSQType.A), QTypeRule(DNSQType.AAAA) }),
	})
end
addAction(NotRule(TrivalQuery()), PoolAction("default"))
addResponseAction(NotRule(TrivalQuery()), AllowResponseAction())

addAction(AllRule(), pdnsmos.SetRestartableAction())

addAction(pdnsmos.GeoSiteRule("steam@cn.txt"), SetTagAction("pool", "cn"))
addAction(TagRule("pool", "cn"), SetTagAction("nextpool", "cn"))

local UntagedAndRule = function(inner)
	return AndRule({ NotRule(TagRule("pool")), NotRule(TagRule("nextpool")), inner })
end
addAction(UntagedAndRule(pdnsmos.GeoSiteRule("geolocation-cn.txt")), SetTagAction("pool", "cn"))
addAction(UntagedAndRule(pdnsmos.GeoSiteRule("geolocation-!cn.txt")), SetTagAction("pool", "un"))
addAction(UntagedAndRule(AllRule()), SetTagAction("pool", "uncn"))

addAction(TagRule("pool", "cn"), PoolAction("cn"))
addAction(TagRule("pool", "un"), PoolAction("un"))
addAction(TagRule("pool", "uncn"), PoolAction("uncn"))

local markCNResponseRule =
	pdnsmos.NftsetResponseAction("comment:1h:inet,geomark,geosite_cn4:inet,geomark,geosite_cn6", false)
local markUNResponseRule =
	pdnsmos.NftsetResponseAction("comment:1h:inet,geomark,geosite_un4:inet,geomark,geosite_un6", false)

addResponseAction(TagRule("nextpool", "un"), markUNResponseRule)
addResponseAction(TagRule("nextpool"), markCNResponseRule)

addResponseAction(
	AndRule({
		TagRule("pool", "cn"),
		NotRule(pdnsmos.GeoIPRule("cn.txt")),
	}),
	SetTagResponseAction("nextpool", "un")
)
addResponseAction(
	AndRule({
		TagRule("pool", "un"),
		pdnsmos.GeoIPRule("cn.txt"),
	}),
	SetTagResponseAction("nextpool", "uncn")
)
addResponseAction(
	AndRule({
		TagRule("pool", "uncn"),
		NotRule(pdnsmos.GeoIPRule("cn.txt")),
	}),
	SetTagResponseAction("nextpool", "un")
)

addResponseAction(
	TagRule("nextpool"),
	LuaResponseAction(function(resp)
		resp.pool = resp:getTag("nextpool")
		resp:restart()
		return DNSResponseAction.Drop
	end)
)

addResponseAction(TagRule("pool", "un"), markUNResponseRule)
addResponseAction(TagRule("pool"), markCNResponseRule)
