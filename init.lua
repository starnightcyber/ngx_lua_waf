require 'config'

local match = string.match

-- 使用find 替换match，可提高匹配效率
local ngxmatch = ngx.re.find
--local ngxmatch=ngx.re.match

-- 简写
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers

-- 获取选项配置，转化为bool型
local optionIsOn = function (options) return options == "on" and true or false end

-- 配置路径，日志和规则
logpath = logdir 
rulepath = RulePath

-- 各项配置
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect = optionIsOn(Redirect)

--截取字符串
function subString(str, k)    
    ts = string.reverse(str)
    _, i = string.find(ts, k)
    m = string.len(ts) - i + 1
    return string.sub(str, 1, m)
end

-- 获取客户端IP地址
function getClientIp()
    IP  = ngx.var.remote_addr 
    if ngx.var.HTTP_X_FORWARDED_FOR then
      IP = ngx.var.HTTP_X_FORWARDED_FOR
    end
        if IP == nil then
            IP  = "unknown"
        end
    IP = subString(IP, "[.]") .. "*"
        return IP
end


-- 获取真实的IP地址
function getRealIp()
    IP  = ngx.var.remote_addr 
    if ngx.var.HTTP_X_FORWARDED_FOR then    --如果用了CDN，判断真实IP
      IP = ngx.var.HTTP_X_FORWARDED_FOR
    end
        if IP == nil then
            IP  = "unknown"
        end
    return IP
end


-- 写入文件操作
function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end


-- 以一定的日志记录格式写入日志文件中 
function log(method, url, data, ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
	-- 此处稍微调整了下格式，将时间放在最前面
	if ua  then
            line = "["..time.."] "..realIp.." "..method.."  \""..servername..url.."\" \""..data.."\"  \""..ua.."\" ==> \""..ruletag.."\"\n"
	else
            line = "["..time.."] "..realIp.." "..method.."  \""..servername..url.."\" \""..data.."\" ==> \""..ruletag.."\"\n"
	end

	local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename, line)
    end
end

-----------------------------------频繁扫描封禁ip----------------------------------

function ban_ip(point)
    local token = getClientIp() .. "_WAF"
    local limit = ngx.shared.limit
    local req,_=limit:get(token)
    if req then
    limit:set(token,req+point,3600)  --发现一次，增加积分，1小时内有效
    else
    limit:set(token,point,3600)
    end
end
 
function get_ban_times()
  local token = getClientIp() .. "_WAF"
  local limit = ngx.shared.limit
        local req,_=limit:get(token)
  if req then
    return req
  else return 0
  end
end
 
function is_ban()
  local ban_times = get_ban_times()
  if ban_times >= 100 then        --超过100积分，ban
    ngx.header.content_type = "text/html;charset=UTF-8"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.exit(ngx.status)
    return true
  else
    return false
  end
  return false
end

------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var, "r")
    if file == nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t, line)
    end
    file:close()
    return(t)
end


-- 加载规则
urlrules = read_rule('url')
argsrules = read_rule('args')
uarules = read_rule('user-agent')
wturlrules = read_rule('whiteurl')
postrules = read_rule('post')
ckrules = read_rule('cookie')


-- 展示禁止页面
function say_html()
	ban_ip(15)      --恶意攻击，罚15分
    if Redirect then
        ngx.header.content_type = "text/html;charset=UTF-8"
    ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end


-- 白名单
function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end


-- 检查文件后缀是否在禁用列表
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngxmatch(ext, rule, "isjo") then
	        log('POST', ngx.var.request_uri, "-", "file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end


function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end


-- args参数判断
function args()
    for _, rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val) == 'table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v = ""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data), rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end


-- url参数判断
function url()
    if UrlDeny then
        for _, rule in pairs(urlrules) do
            if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end


-- ua判断
function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua, rule, "isjo") then
                log('UA', ngx.var.request_uri, "-", rule)
                say_html()
            return true
            end
        end
    end
    return false
end


-- post body判断
function body(data)
    for _,rule in pairs(postrules) do
        if rule ~= "" and data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
            log('POST', ngx.var.request_uri, data, rule)
            say_html()
            return true
        end
    end
    return false
end


-- cookie判断
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _, rule in pairs(ckrules) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                log('Cookie', ngx.var.request_uri, "-", rule)
                say_html()
            return true
            end
        end
    end
    return false
end


-- CC限速
function denycc()
    if CCDeny then
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getRealIp()
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
				limit:incr(token,1)
				ban_ip(req - CCcount)  --CC攻击，罚分
				ngx.header.content_type = "text/html"
				ngx.status = ngx.HTTP_FORBIDDEN
                ngx.say("老哥你手速也忒快了吧，要不休息"..CCcount.."秒？")
                ngx.exit(ngx.status)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end


-- header头边界 what ?
function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end


-- 判断是否在白名单列表中
function whiteip()
    if next(ipWhitelist) ~= nil then
        for _, ip in pairs(ipWhitelist) do
            if getClientIp() == ip then
                return true
            end
        end
    end
        return false
end


-- 判断是否在黑名单列表
function blockip()
     if next(ipBlocklist) ~= nil then
         for _, ip in pairs(ipBlocklist) do
             if getClientIp() == ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end


-- This is the End
