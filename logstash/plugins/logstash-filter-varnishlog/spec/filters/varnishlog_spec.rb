# encoding: utf-8
require 'spec_helper'
require "tempfile"
require "stud/temporary"
require "logstash/filters/varnishlog"

# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
end

describe LogStash::Filters::VarnishLog do

  describe "check param filter" do

    let(:config) do <<-CONFIG
      filter {
        varnishlog {
           param_list => { "Request" => { "ReqHeader" => { "X-Akamai-Edgescape" => [ ] "Cookie" => [ ]  } } }
        }
      }
    CONFIG
    end

    sample("*   << Request  >> 250021080 \n-   Begin          req 248188602 rxreq\n-   Timestamp      Start: 1452232076.035625 0.000000 0.000000\n-   Timestamp      Req: 1452232074.035625 0.000000 0.000000\n-   ReqStart       1.1.1.1 45944\n-   ReqMethod      GET\n-   ReqURL         /xyz/image/123456789.jpg\n-   ReqProtocol    HTTP/1.1\n-   ReqHeader      Accept: image/webp,image/*,*/*;q=0.8\n-   ReqHeader      User-Agent: Mozilla/5.0 (Linux; Android 5.0.2; SM-T710 Build/LRX22G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Safari/537.36\n-   ReqHeader      Accept-Language: en-AU,en-US;q=0.8\n-   ReqHeader      X-Requested-With: android.COOKIEApplication\n-   ReqHeader      Cookie: COOKIE_WAS_HERE=tablet\n-   ReqHeader      X-Akamai-Edgescape: georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0\n-   ReqHeader      True-Client-IP: 1.1.1.1\n-   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true\n-   ReqHeader      TE:  chunked;q=1.0\n-   ReqHeader      Connection: TE, keep-alive\n-   ReqHeader      Accept-Encoding: gzip\n-   ReqHeader      Akamai-Origin-Hop: 2\n-   ReqHeader      Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      Host: www.COOKIE.net.au\n-   ReqHeader      Cache-Control: max-age=3600\n-   ReqHeader      X-NS-Forwarded-For: 1.1.1.1\n-   ReqUnset       X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1, 1.1.1.1\n-   VCL_call       RECV\n-   ReqUnset       Cookie: COOKIE_WAS_HERE=tablet\n-   VCL_acl        NO_MATCH COOKIEonly\n-\n-   ReqHeader      X-Restarts: 0\n-   ReqURL         /xyz/image/123456789.jpg\n-   VCL_return     hash\n-   VCL_call       HASH\n-   VCL_return     lookup\n-   Hit            2395082803\n-   VCL_call       HIT\n-   ReqHeader      X-Varnish-f: 86400.000\n-   ReqHeader      X-Varnish-e: -22.466\n-   ReqHeader      X-Varnish-c: 86400.000\n-   ReqHeader      X-Varnish-g: grace\n-   VCL_return     deliver\n-   Link           bereq 250021081 bgfetch\n-   Timestamp      Fetch: 1452232074.035807 0.000181 0.000181\n-   RespProtocol   HTTP/1.1\n-   RespStatus     200\n-   RespReason     OK\n-   RespHeader     Date: Fri, 08 Jan 2016 05:46:32 GMT\n-   RespHeader     Server: Apache\n-   RespHeader     Last-Modified: Mon, 04 Jan 2016 05:31:40 GMT\n-   RespHeader     Content-Length: 53161\n-   RespHeader     Content-Type: image/jpeg\n-   RespHeader     Cache-Control: max-age=60\n-   RespHeader     X-Varnish: 250021080 247599155\n-   RespHeader     Age: 82\n-   RespHeader     Via: 1.1 varnish-v4\n-   VCL_call       DELIVER\n-   RespUnset      Via: 1.1 varnish-v4\n-   RespUnset      X-Varnish: 250021080 247599155\n-   RespUnset      Age: 82\n-   RespUnset      Server: Apache\n-   VCL_return     deliver\n-   Timestamp      Process: 1452232074.035823 0.000197 0.000016\n-   Debug          \"RES_MODE 2\"\n-   RespHeader     Connection: keep-alive\n-   RespHeader     Accept-Ranges: bytes\n-   Timestamp      Resp: 1452232074.155180 0.119554 0.119357\n-   Debug          \"XXX REF 1\"\n-   ReqAcct        918 0 918 224 53161 53385\n-   End            ") do

       insist { subject['message_type'] } == "Request"
       insist { subject['@timestamp'].to_s } == "2016-01-08T05:47:56.071Z"
       insist { subject['request_header'] } == ["Accept", "User-Agent", "Accept-Language", "X-Requested-With", "Cookie", "X-Akamai-Edgescape", "True-Client-IP", "X-Akamai-CONFIG-LOG-DETAIL", "TE", "Connection", "Accept-Encoding", "Akamai-Origin-Hop", "Via", "X-Forwarded-For", "Host", "Cache-Control", "X-NS-Forwarded-For", "X-Restarts", "X-Varnish-f", "X-Varnish-e", "X-Varnish-c", "X-Varnish-g"]
       insist { subject['timestamp']['Start'].to_s } == "2016-01-08 16:47:56 +1100"
       insist { subject['timestamp']['Req'].to_s } == "2016-01-08 16:47:54 +1100"
       insist { subject['ReqHeader']['Cookie']['raw'] } == "COOKIE_WAS_HERE=tablet"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['raw'] } == "georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0"
       insist { subject['ReqHeader'].length } == 2
       insist { subject['ReqHeader'].keys } == [ "Cookie", "X-Akamai-Edgescape" ]
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].length } == 1
       insist { subject['ReqHeader']['Cookie'].length } == 1
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].keys } == [ "raw" ]
       insist { subject['ReqHeader']['Cookie'].keys } == [ "raw" ]
       insist { subject['message'] }.nil?
       insist { subject['tags'] }.nil?
    end

  end

  describe "check param filte detail" do

    let(:config) do <<-CONFIG
      filter {
        varnishlog {
           param_list => { "Request" => { "ReqHeader" => { "X-Akamai-Edgescape" => [ ",", "=" ] "Cookie" => [ "=" ]  } } }
        }
      }
    CONFIG
    end

    sample("*   << Request  >> 250021080 \n-   Begin          req 248188602 rxreq\n-   Timestamp      Start: 1452232076.035625 0.000000 0.000000\n-   Timestamp      Req: 1452232074.035625 0.000000 0.000000\n-   ReqStart       1.1.1.1 45944\n-   ReqMethod      GET\n-   ReqURL         /xyz/image/123456789.jpg\n-   ReqProtocol    HTTP/1.1\n-   ReqHeader      Accept: image/webp,image/*,*/*;q=0.8\n-   ReqHeader      User-Agent: Mozilla/5.0 (Linux; Android 5.0.2; SM-T710 Build/LRX22G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Safari/537.36\n-   ReqHeader      Accept-Language: en-AU,en-US;q=0.8\n-   ReqHeader      X-Requested-With: android.COOKIEApplication\n-   ReqHeader      Cookie: COOKIE_WAS_HERE=tablet\n-   ReqHeader      X-Akamai-Edgescape: georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0\n-   ReqHeader      True-Client-IP: 1.1.1.1\n-   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true\n-   ReqHeader      TE:  chunked;q=1.0\n-   ReqHeader      Connection: TE, keep-alive\n-   ReqHeader      Accept-Encoding: gzip\n-   ReqHeader      Akamai-Origin-Hop: 2\n-   ReqHeader      Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      Host: www.COOKIE.net.au\n-   ReqHeader      Cache-Control: max-age=3600\n-   ReqHeader      X-NS-Forwarded-For: 1.1.1.1\n-   ReqUnset       X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1, 1.1.1.1\n-   VCL_call       RECV\n-   ReqUnset       Cookie: COOKIE_WAS_HERE=tablet\n-   VCL_acl        NO_MATCH COOKIEonly\n-\n-   ReqHeader      X-Restarts: 0\n-   ReqURL         /xyz/image/123456789.jpg\n-   VCL_return     hash\n-   VCL_call       HASH\n-   VCL_return     lookup\n-   Hit            2395082803\n-   VCL_call       HIT\n-   ReqHeader      X-Varnish-f: 86400.000\n-   ReqHeader      X-Varnish-e: -22.466\n-   ReqHeader      X-Varnish-c: 86400.000\n-   ReqHeader      X-Varnish-g: grace\n-   VCL_return     deliver\n-   Link           bereq 250021081 bgfetch\n-   Timestamp      Fetch: 1452232074.035807 0.000181 0.000181\n-   RespProtocol   HTTP/1.1\n-   RespStatus     200\n-   RespReason     OK\n-   RespHeader     Date: Fri, 08 Jan 2016 05:46:32 GMT\n-   RespHeader     Server: Apache\n-   RespHeader     Last-Modified: Mon, 04 Jan 2016 05:31:40 GMT\n-   RespHeader     Content-Length: 53161\n-   RespHeader     Content-Type: image/jpeg\n-   RespHeader     Cache-Control: max-age=60\n-   RespHeader     X-Varnish: 250021080 247599155\n-   RespHeader     Age: 82\n-   RespHeader     Via: 1.1 varnish-v4\n-   VCL_call       DELIVER\n-   RespUnset      Via: 1.1 varnish-v4\n-   RespUnset      X-Varnish: 250021080 247599155\n-   RespUnset      Age: 82\n-   RespUnset      Server: Apache\n-   VCL_return     deliver\n-   Timestamp      Process: 1452232074.035823 0.000197 0.000016\n-   Debug          \"RES_MODE 2\"\n-   RespHeader     Connection: keep-alive\n-   RespHeader     Accept-Ranges: bytes\n-   Timestamp      Resp: 1452232074.155180 0.119554 0.119357\n-   Debug          \"XXX REF 1\"\n-   ReqAcct        918 0 918 224 53161 53385\n-   End            ") do

       insist { subject['message_type'] } == "Request"
       insist { subject['@timestamp'].to_s } == "2016-01-08T05:47:56.071Z"
       insist { subject['request_header'] } == ["Accept", "User-Agent", "Accept-Language", "X-Requested-With", "Cookie", "X-Akamai-Edgescape", "True-Client-IP", "X-Akamai-CONFIG-LOG-DETAIL", "TE", "Connection", "Accept-Encoding", "Akamai-Origin-Hop", "Via", "X-Forwarded-For", "Host", "Cache-Control", "X-NS-Forwarded-For", "X-Restarts", "X-Varnish-f", "X-Varnish-e", "X-Varnish-c", "X-Varnish-g"]
       insist { subject['timestamp']['Start'].to_s } == "2016-01-08 16:47:56 +1100"
       insist { subject['timestamp']['Req'].to_s } == "2016-01-08 16:47:54 +1100"
       insist { subject['ReqHeader'].length } == 2
       insist { subject['ReqHeader'].keys } == [ "Cookie", "X-Akamai-Edgescape" ]
       insist { subject['ReqHeader']['Cookie'].length } == 2
       insist { subject['ReqHeader']['Cookie'].keys } == [ "raw", "COOKIE_WAS_HERE" ]
       insist { subject['ReqHeader']['Cookie']['raw'] } == "COOKIE_WAS_HERE=tablet"
       insist { subject['ReqHeader']['Cookie']['COOKIE_WAS_HERE'] } == "tablet"
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].length } == 13
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].keys } == [ "raw", "georegion","country_code","region_code","city","lat","long","timezone","continent","throughput","bw","asnum","location_id" ]
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['raw'] } == "georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['georegion'] } == "16"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['country_code'] } == "AU"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['region_code'] } == "NSW"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['city'] } == "SYDNEY"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['lat'] } == "-33.88"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['long'] } == "151.22"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['timezone'] } == "GMT+10"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['continent'] } == "OC"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['throughput'] } == "vhigh"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['bw'] } == "5000"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['asnum'] } == "7545"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['location_id'] } == "0"
       insist { subject['geoip']['latitude'] } == -33.88
       insist { subject['geoip']['longitude'] } == 151.22
       insist { subject['geoip']['location'] } == [ 151.22, -33.88 ]
       insist { subject['geoip'].length } == 3
       insist { subject['geoip'].keys } == [ "location", "latitude", "longitude" ]
       insist { subject['message'] }.nil?
       insist { subject['tags'] }.nil?
    end

  end

  describe "check param filte detail simple" do

    let(:config) do <<-CONFIG
      filter {
        varnishlog {
           param_list => { "Request" => { "ReqHeader" => { "X-Akamai-Edgescape" => [ ",", "=" ] } } }
        }
      }
    CONFIG
    end

    sample("*   << Request  >> 250021080 \n-   Begin          req 248188602 rxreq\n-   Timestamp      Start: 1452232076.035625 0.000000 0.000000\n-   Timestamp      Req: 1452232074.035625 0.000000 0.000000\n-   ReqStart       1.1.1.1 45944\n-   ReqMethod      GET\n-   ReqURL         /xyz/image/123456789.jpg\n-   ReqProtocol    HTTP/1.1\n-   ReqHeader      Accept: image/webp,image/*,*/*;q=0.8\n-   ReqHeader      User-Agent: Mozilla/5.0 (Linux; Android 5.0.2; SM-T710 Build/LRX22G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Safari/537.36\n-   ReqHeader      Accept-Language: en-AU,en-US;q=0.8\n-   ReqHeader      X-Requested-With: android.COOKIEApplication\n-   ReqHeader      Cookie: COOKIE_WAS_HERE=tablet\n-   ReqHeader      X-Akamai-Edgescape: georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0\n-   ReqHeader      True-Client-IP: 1.1.1.1\n-   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true\n-   ReqHeader      TE:  chunked;q=1.0\n-   ReqHeader      Connection: TE, keep-alive\n-   ReqHeader      Accept-Encoding: gzip\n-   ReqHeader      Akamai-Origin-Hop: 2\n-   ReqHeader      Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      Host: www.COOKIE.net.au\n-   ReqHeader      Cache-Control: max-age=3600\n-   ReqHeader      X-NS-Forwarded-For: 1.1.1.1\n-   ReqUnset       X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1, 1.1.1.1\n-   VCL_call       RECV\n-   ReqUnset       Cookie: COOKIE_WAS_HERE=tablet\n-   VCL_acl        NO_MATCH COOKIEonly\n-\n-   ReqHeader      X-Restarts: 0\n-   ReqURL         /xyz/image/123456789.jpg\n-   VCL_return     hash\n-   VCL_call       HASH\n-   VCL_return     lookup\n-   Hit            2395082803\n-   VCL_call       HIT\n-   ReqHeader      X-Varnish-f: 86400.000\n-   ReqHeader      X-Varnish-e: -22.466\n-   ReqHeader      X-Varnish-c: 86400.000\n-   ReqHeader      X-Varnish-g: grace\n-   VCL_return     deliver\n-   Link           bereq 250021081 bgfetch\n-   Timestamp      Fetch: 1452232074.035807 0.000181 0.000181\n-   RespProtocol   HTTP/1.1\n-   RespStatus     200\n-   RespReason     OK\n-   RespHeader     Date: Fri, 08 Jan 2016 05:46:32 GMT\n-   RespHeader     Server: Apache\n-   RespHeader     Last-Modified: Mon, 04 Jan 2016 05:31:40 GMT\n-   RespHeader     Content-Length: 53161\n-   RespHeader     Content-Type: image/jpeg\n-   RespHeader     Cache-Control: max-age=60\n-   RespHeader     X-Varnish: 250021080 247599155\n-   RespHeader     Age: 82\n-   RespHeader     Via: 1.1 varnish-v4\n-   VCL_call       DELIVER\n-   RespUnset      Via: 1.1 varnish-v4\n-   RespUnset      X-Varnish: 250021080 247599155\n-   RespUnset      Age: 82\n-   RespUnset      Server: Apache\n-   VCL_return     deliver\n-   Timestamp      Process: 1452232074.035823 0.000197 0.000016\n-   Debug          \"RES_MODE 2\"\n-   RespHeader     Connection: keep-alive\n-   RespHeader     Accept-Ranges: bytes\n-   Timestamp      Resp: 1452232074.155180 0.119554 0.119357\n-   Debug          \"XXX REF 1\"\n-   ReqAcct        918 0 918 224 53161 53385\n-   End            ") do

       insist { subject['message_type'] } == "Request"
       insist { subject['@timestamp'].to_s } == "2016-01-08T05:47:56.071Z"
       insist { subject['request_header'] } == ["Accept", "User-Agent", "Accept-Language", "X-Requested-With", "Cookie", "X-Akamai-Edgescape", "True-Client-IP", "X-Akamai-CONFIG-LOG-DETAIL", "TE", "Connection", "Accept-Encoding", "Akamai-Origin-Hop", "Via", "X-Forwarded-For", "Host", "Cache-Control", "X-NS-Forwarded-For", "X-Restarts", "X-Varnish-f", "X-Varnish-e", "X-Varnish-c", "X-Varnish-g"]
       insist { subject['timestamp']['Start'].to_s } == "2016-01-08 16:47:56 +1100"
       insist { subject['timestamp']['Req'].to_s } == "2016-01-08 16:47:54 +1100"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['raw'] } == "georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['georegion'] } == "16"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['country_code'] } == "AU"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['region_code'] } == "NSW"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['city'] } == "SYDNEY"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['lat'] } == "-33.88"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['long'] } == "151.22"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['timezone'] } == "GMT+10"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['continent'] } == "OC"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['throughput'] } == "vhigh"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['bw'] } == "5000"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['asnum'] } == "7545"
       insist { subject['ReqHeader']['X-Akamai-Edgescape']['location_id'] } == "0"
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].length } == 13
       insist { subject['ReqHeader']['X-Akamai-Edgescape'].keys } == [ "raw", "georegion","country_code","region_code","city","lat","long","timezone","continent","throughput","bw","asnum","location_id" ]
       insist { subject['geoip']['latitude'] } == -33.88
       insist { subject['geoip']['longitude'] } == 151.22
       insist { subject['geoip']['location'] } == [ 151.22, -33.88 ]
       insist { subject['geoip'].length } == 3
       insist { subject['geoip'].keys } == [ "location", "latitude", "longitude" ]
       insist { subject['message'] }.nil?
       insist { subject['tags'] }.nil?
    end

  end

  describe "check param filte detail" do

    let(:config) do <<-CONFIG
      filter {
        varnishlog {
           param_list => { "Request" => { "ReqMethod" => [ ] } }
        }
      }
    CONFIG
    end

    sample("*   << Request  >> 250021080 \n-   Begin          req 248188602 rxreq\n-   Timestamp      Start: 1452232076.035625 0.000000 0.000000\n-   Timestamp      Req: 1452232074.035625 0.000000 0.000000\n-   ReqStart       1.1.1.1 45944\n-   ReqMethod      GET\n-   ReqURL         /xyz/image/123456789.jpg\n-   ReqProtocol    HTTP/1.1\n-   ReqHeader      Accept: image/webp,image/*,*/*;q=0.8\n-   ReqHeader      User-Agent: Mozilla/5.0 (Linux; Android 5.0.2; SM-T710 Build/LRX22G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Safari/537.36\n-   ReqHeader      Accept-Language: en-AU,en-US;q=0.8\n-   ReqHeader      X-Requested-With: android.COOKIEApplication\n-   ReqHeader      Cookie: COOKIE_WAS_HERE=tablet\n-   ReqHeader      X-Akamai-Edgescape: georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0\n-   ReqHeader      True-Client-IP: 1.1.1.1\n-   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true\n-   ReqHeader      TE:  chunked;q=1.0\n-   ReqHeader      Connection: TE, keep-alive\n-   ReqHeader      Accept-Encoding: gzip\n-   ReqHeader      Akamai-Origin-Hop: 2\n-   ReqHeader      Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      Host: www.COOKIE.net.au\n-   ReqHeader      Cache-Control: max-age=3600\n-   ReqHeader      X-NS-Forwarded-For: 1.1.1.1\n-   ReqUnset       X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1, 1.1.1.1\n-   VCL_call       RECV\n-   ReqUnset       Cookie: COOKIE_WAS_HERE=tablet\n-   VCL_acl        NO_MATCH COOKIEonly\n-\n-   ReqHeader      X-Restarts: 0\n-   ReqURL         /xyz/image/123456789.jpg\n-   VCL_return     hash\n-   VCL_call       HASH\n-   VCL_return     lookup\n-   Hit            2395082803\n-   VCL_call       HIT\n-   ReqHeader      X-Varnish-f: 86400.000\n-   ReqHeader      X-Varnish-e: -22.466\n-   ReqHeader      X-Varnish-c: 86400.000\n-   ReqHeader      X-Varnish-g: grace\n-   VCL_return     deliver\n-   Link           bereq 250021081 bgfetch\n-   Timestamp      Fetch: 1452232074.035807 0.000181 0.000181\n-   RespProtocol   HTTP/1.1\n-   RespStatus     200\n-   RespReason     OK\n-   RespHeader     Date: Fri, 08 Jan 2016 05:46:32 GMT\n-   RespHeader     Server: Apache\n-   RespHeader     Last-Modified: Mon, 04 Jan 2016 05:31:40 GMT\n-   RespHeader     Content-Length: 53161\n-   RespHeader     Content-Type: image/jpeg\n-   RespHeader     Cache-Control: max-age=60\n-   RespHeader     X-Varnish: 250021080 247599155\n-   RespHeader     Age: 82\n-   RespHeader     Via: 1.1 varnish-v4\n-   VCL_call       DELIVER\n-   RespUnset      Via: 1.1 varnish-v4\n-   RespUnset      X-Varnish: 250021080 247599155\n-   RespUnset      Age: 82\n-   RespUnset      Server: Apache\n-   VCL_return     deliver\n-   Timestamp      Process: 1452232074.035823 0.000197 0.000016\n-   Debug          \"RES_MODE 2\"\n-   RespHeader     Connection: keep-alive\n-   RespHeader     Accept-Ranges: bytes\n-   Timestamp      Resp: 1452232074.155180 0.119554 0.119357\n-   Debug          \"XXX REF 1\"\n-   ReqAcct        918 0 918 224 53161 53385\n-   End            ") do

       insist { subject['message_type'] } == "Request"
       insist { subject['@timestamp'].to_s } == "2016-01-08T05:47:56.071Z"
       insist { subject['request_header'] } == ["Accept", "User-Agent", "Accept-Language", "X-Requested-With", "Cookie", "X-Akamai-Edgescape", "True-Client-IP", "X-Akamai-CONFIG-LOG-DETAIL", "TE", "Connection", "Accept-Encoding", "Akamai-Origin-Hop", "Via", "X-Forwarded-For", "Host", "Cache-Control", "X-NS-Forwarded-For", "X-Restarts", "X-Varnish-f", "X-Varnish-e", "X-Varnish-c", "X-Varnish-g"]
       insist { subject['timestamp']['Start'].to_s } == "2016-01-08 16:47:56 +1100"
       insist { subject['timestamp']['Req'].to_s } == "2016-01-08 16:47:54 +1100"
       insist { subject['ReqMethod'] } == "GET"
       insist { subject['message'] }.nil?
       insist { subject['tags'] }.nil?
    end

  end

  describe "clear event" do

    let(:config) do <<-CONFIG
      filter {
        varnishlog {
        }
      }
    CONFIG
    end

    sample("*   << Request  >> 250021080 \n-   Begin          req 248188602 rxreq\n-   Timestamp      Start: 1452232076.035625 0.000000 0.000000\n-   Timestamp      Req: 1452232074.035625 0.000000 0.000000\n-   ReqStart       1.1.1.1 45944\n-   ReqMethod      GET\n-   ReqURL         /xyz/image/123456789.jpg\n-   ReqProtocol    HTTP/1.1\n-   ReqHeader      Accept: image/webp,image/*,*/*;q=0.8\n-   ReqHeader      User-Agent: Mozilla/5.0 (Linux; Android 5.0.2; SM-T710 Build/LRX22G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Safari/537.36\n-   ReqHeader      Accept-Language: en-AU,en-US;q=0.8\n-   ReqHeader      X-Requested-With: android.COOKIEApplication\n-   ReqHeader      Cookie: COOKIE_WAS_HERE=tablet\n-   ReqHeader      X-Akamai-Edgescape: georegion=16,country_code=AU,region_code=NSW,city=SYDNEY,lat=-33.88,long=151.22,timezone=GMT+10,continent=OC,throughput=vhigh,bw=5000,asnum=7545,location_id=0\n-   ReqHeader      True-Client-IP: 1.1.1.1\n-   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true\n-   ReqHeader      TE:  chunked;q=1.0\n-   ReqHeader      Connection: TE, keep-alive\n-   ReqHeader      Accept-Encoding: gzip\n-   ReqHeader      Akamai-Origin-Hop: 2\n-   ReqHeader      Via: 1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      Host: www.COOKIE.net.au\n-   ReqHeader      Cache-Control: max-age=3600\n-   ReqHeader      X-NS-Forwarded-For: 1.1.1.1\n-   ReqUnset       X-Forwarded-For: 1.1.1.1, 1.1.1.1\n-   ReqHeader      X-Forwarded-For: 1.1.1.1, 1.1.1.1, 1.1.1.1\n-   VCL_call       RECV\n-   ReqUnset       Cookie: COOKIE_WAS_HERE=tablet\n-   VCL_acl        NO_MATCH COOKIEonly\n-\n-   ReqHeader      X-Restarts: 0\n-   ReqURL         /xyz/image/123456789.jpg\n-   VCL_return     hash\n-   VCL_call       HASH\n-   VCL_return     lookup\n-   Hit            2395082803\n-   VCL_call       HIT\n-   ReqHeader      X-Varnish-f: 86400.000\n-   ReqHeader      X-Varnish-e: -22.466\n-   ReqHeader      X-Varnish-c: 86400.000\n-   ReqHeader      X-Varnish-g: grace\n-   VCL_return     deliver\n-   Link           bereq 250021081 bgfetch\n-   Timestamp      Fetch: 1452232074.035807 0.000181 0.000181\n-   RespProtocol   HTTP/1.1\n-   RespStatus     200\n-   RespReason     OK\n-   RespHeader     Date: Fri, 08 Jan 2016 05:46:32 GMT\n-   RespHeader     Server: Apache\n-   RespHeader     Last-Modified: Mon, 04 Jan 2016 05:31:40 GMT\n-   RespHeader     Content-Length: 53161\n-   RespHeader     Content-Type: image/jpeg\n-   RespHeader     Cache-Control: max-age=60\n-   RespHeader     X-Varnish: 250021080 247599155\n-   RespHeader     Age: 82\n-   RespHeader     Via: 1.1 varnish-v4\n-   VCL_call       DELIVER\n-   RespUnset      Via: 1.1 varnish-v4\n-   RespUnset      X-Varnish: 250021080 247599155\n-   RespUnset      Age: 82\n-   RespUnset      Server: Apache\n-   VCL_return     deliver\n-   Timestamp      Process: 1452232074.035823 0.000197 0.000016\n-   Debug          \"RES_MODE 2\"\n-   RespHeader     Connection: keep-alive\n-   RespHeader     Accept-Ranges: bytes\n-   Timestamp      Resp: 1452232074.155180 0.119554 0.119357\n-   Debug          \"XXX REF 1\"\n-   ReqAcct        918 0 918 224 53161 53385\n-   End            ") do
       insist { subject }.nil?
    end

  end

end

