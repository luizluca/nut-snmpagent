#
#
#
module CachedMethod
    NOCACHE_SUFIX="_nocache"

    def cached(method, args, ttf=@cache_ttf)
        key=[method, args]
        return nil if not @cache or not @cache.include? key
        (result, timestamp)=@cache[key]
        return nil if Time.now-timestamp>ttf
        return result
    end

    def cache(method, result, args)
        key=[method, args]
        @cache=Hash.new if not @cache
        @cache[key]=[result,Time.now]
        result
    end

    def cache_method(method_sym, ttl=nil)
        cached_version=<<-EOM
            alias_method :#{method_sym.to_s + NOCACHE_SUFIX}, :#{method_sym.to_s}
            def #{method_sym.to_s}(*args)
                value = cached(:#{method_sym.to_s}, args #{",#{ttl}" if ttl})
                return value if not value==nil
                return cache(:#{method_sym.to_s},#{method_sym.to_s + NOCACHE_SUFIX}(*args), args)
            end
        EOM
        class_eval cached_version
    end

    attr_accessor :cache_ttf
end
