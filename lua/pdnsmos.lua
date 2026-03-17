local M = {}

if IsFFIEnv == nil then
    local function wrapper(s)
        return "IsFFIEnv = true\nreturn require(\"pdnsmos\")." .. s
    end
    function serialize(val)
        local t = type(val)
        if t == "string" then
            return string.format("%q", val)
        elseif t == "number" or t == "boolean" or t == "nil" then
            return tostring(val)
        else
            error("failed to serialize value")
        end
    end
    M.SetRestartableAction = function()
        return LuaFFIPerThreadAction(wrapper("SetRestartableAction()"))
    end

    M.RestartCountRule = function(count)
        return LuaFFIPerThreadRule(wrapper(
                                       string.format("RestartCountRule(%d)",
                                                     count)))
    end

    M.GeoSiteRule = function(path)
        return LuaFFIPerThreadRule(wrapper(
                                       string.format("GeoSiteRule(%q)",
                                                     "/geosite/" .. path)))
    end

    M.GeoIPRule = function(path, invert)
        return LuaFFIPerThreadRule(wrapper(
                                       string.format("GeoIPRule(%q, %s)",
                                                     "/geoip/" .. path, invert)))
    end
else
    local ffi = require("ffi")
    ffi.cdef([[
        bool dnsdist_ffi_dnsquestion_set_restartable(dnsdist_ffi_dnsquestion_t* ptr);
        unsigned char dnsdist_ffi_dnsresponse_get_restart_count(dnsdist_ffi_dnsresponse_t* ptr);
        void my_dnsdist_ffi_action(dnsdist_ffi_dnsquestion_t* ptr);
        void *ruder_load_site_rule(const char *path);
        bool ruder_match_query_for_site_rule(dnsdist_ffi_dnsquestion_t* ptr, void *rule);
        void *ruder_load_ip_rule(const char *path);
        bool ruder_match_query_for_ip_rule(dnsdist_ffi_dnsquestion_t* ptr, void *rule, bool invert);
    ]])

    local C = ffi.C
    local lib = ffi.load("/app/c/libpdnsmos.so")

    M.SetRestartableAction = function()
        return function(ptr)
            C.dnsdist_ffi_dnsquestion_set_restartable(ptr)
            return DNSAction.None
        end
    end

    M.RestartCountRule = function(count)
        return function(ptr)
            print("Got " ..
                      tostring(
                          tonumber(
                              C.dnsdist_ffi_dnsresponse_get_restart_count(ptr))))
            return tonumber(C.dnsdist_ffi_dnsresponse_get_restart_count(ptr)) >=
                       count
        end
    end

    M.GeoSiteRule = function(path)
        local ruleset = lib.ruder_load_site_rule(path)
        if ruleset == ffi.NULL then error("cannot build ruleset") end
        return function(ptr)
            return lib.ruder_match_query_for_site_rule(ptr, ruleset)
        end
    end

    M.GeoIPRule = function(path, invert)
        local ruleset = lib.ruder_load_ip_rule(path)
        if ruleset == ffi.NULL then error("cannot build ruleset") end
        return function(ptr)
            return lib.ruder_match_query_for_ip_rule(ptr, ruleset, invert)
        end
    end
end

return M
