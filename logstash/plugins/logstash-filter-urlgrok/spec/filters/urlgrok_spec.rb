# encoding: utf-8
require 'spec_helper'
require "tempfile"
require "stud/temporary"
require "logstash/filters/urlgrok"

# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
end

describe LogStash::Filters::UrlGrok do
  describe "it should work" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"1\", \"pattern\": \"^\/([^\/]+)\/code\/(.*)\", \"category_tags\": { \"tag\": \"code\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"2\", \"pattern\": \"^\/([^\/]+)\/cb\/.*.(jpg|png|gif)$\", \"category_tags\": { \"tag\": \"image\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"3\", \"pattern\": \"^\/([^\/]+)\/cb\/\", \"category_tags\": { \"tag\": \"cb\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"4\", \"pattern\": \"^\/([^\/]+)\/contentblob\/(.*)\", \"category_tags\": { \"tag\": \"contentblob\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"5\", \"pattern\": \"^\/(.+)\/feed\/(.*)\", \"category_tags\": { \"tag\": \"feed\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"6\", \"pattern\": \"^\/([^\/]+)\/studio\/(.*)\", \"category_tags\": { \"tag\": \"studio\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"7\", \"pattern\": \"^\/([^\/]+)\/rimage\/(.*)\", \"category_tags\": { \"tag\": \"rimage\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"8\", \"pattern\": \"^\/([^\/]+)\/image\/(.*)\", \"category_tags\": { \"tag\": \"image\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"9\", \"pattern\": \"^\/([^\/]+)\/lb\/(.*)\", \"category_tags\": { \"tag\": \"lb\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"10\", \"pattern\": \"^\/([^\/]+)\/linkableblob\/(.*)\", \"category_tags\": { \"tag\": \"linkableblob\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"11\", \"pattern\": \"^\/(.+)\/pagination\/([a-z\/]+)\/([0-9]+)$\", \"category_tags\": { \"tag\": \"pagination\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"12\", \"pattern\": \"^\/(.+)\/service\/([a-z\/]+)\/([0-9]+)$\", \"category_tags\": { \"tag\": \"service\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"13\", \"pattern\": \"^\/([^\/]+)\/ajax\/(.*)\", \"category_tags\": { \"tag\": \"ajax\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"14\", \"pattern\": \"^\/([^\/]+)\/map\/id=(.*)\", \"category_tags\": { \"tag\": \"map\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"15\", \"pattern\": \"^\/([^\/]+)\/map\/$\", \"category_tags\": { \"tag\": \"map\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"16\", \"pattern\": \"^\/([^\/]+)\/media\/(.*)\", \"category_tags\": { \"tag\": \"media\", \"seg1\": \"3\", \"seg2\": \"4\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"17\", \"pattern\": \"^\/([^\/]+)\/archive\/(.*)\", \"category_tags\": { \"tag\": \"archive\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"18\", \"pattern\": \"^\/([^\/]+)\/topics\/(.*)\", \"category_tags\": { \"tag\": \"topics\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"19\", \"pattern\": \"^\/([^\/]+)\/topic\/(.*)\", \"category_tags\": { \"tag\": \"topic\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"20\", \"pattern\": \"^\/([^\/]+)\/([^\/]+)\/topic\/(.*)\", \"category_tags\": { \"tag\": \"topic\", \"seg1\": \"2\", \"seg2\": \"4\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"21\", \"pattern\": \"^\/([^\/]+)\/persontopic\/(.*)\", \"category_tags\": { \"tag\": \"persontopic\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"22\", \"pattern\": \"^\/([^\/]+)\/bytopic\/(.*)\", \"category_tags\": { \"tag\": \"bytopic\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"23\", \"pattern\": \"^\/probe\", \"category_tags\": { \"tag\": \"probe\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"24\", \"pattern\": \"^\/news\/[0-9]{4}-[0-9]{2}-[0-9]{1,2}\", \"category_tags\": { \"tag\": \"detailed_page\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"25\", \"pattern\": \"^\/([a-z]+)\/im(?:[g]|(age))\", \"category_tags\": { \"tag\": \"image\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"26\", \"pattern\": \"^\/([a-z]+)\/([0-9]+)$\", \"category_tags\": { \"tag\": \"cm_id_lookup\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"27\", \"pattern\": \"^\/([a-z]+)\/([a-z]+)-([a-z]+)\", \"category_tags\": { \"tag\": \"person\", \"seg1\": \"2\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"28\", \"pattern\": \"^\/([a-z]+)\/programs\/index=\", \"category_tags\": { \"tag\": \"index\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"29\", \"pattern\": \"^\/([a-z]+)\/programs\/([a-z0-9]+)\", \"category_tags\": { \"tag\": \"detailed_page\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"30\", \"pattern\": \"^\/radionational\/([a-z]+)\", \"category_tags\": { \"tag\": \"detailed_page\", \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"31\", \"pattern\": \"^\/radionational\/([0-9]+)\", \"category_tags\": { \"seg1\": \"3\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"32\", \"pattern\": \"^\/rn\/([a-z0-9]+)\", \"category_tags\": { \"seg1\": \"2\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"33\", \"pattern\": \"^\/unleashed\/([a-z]+)\/([a-z0-9]+).htm\", \"category_tags\": { \"tag\": \"detailed_page\", \"seg1\": \"2\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"34\", \"pattern\": \"^\/unleashed\/([a-z0-9]+).htm\", \"category_tags\": { \"tag\": \"detailed_page\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"35\", \"pattern\": \"^\/([a-z]+)\/([a-z-]+)\", \"category_tags\": { \"tag\": \"landing_page\", \"seg1\": \"2\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"36\", \"pattern\": \"^\/([a-z0-9]+)$\", \"category_tags\": { \"tag\": \"landing_page\" } }")
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"37\", \"pattern\": \"^\/([a-z0-9]+)\/$\", \"category_tags\": { \"tag\": \"landing_page\" } }")

      fd.puts("{ \"type\": \"input\", \"patternkey\": \"1\", \"pattern\": \"^\/radionational\" }")
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"2\", \"pattern\": \"^\/rn\" }")
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"3\", \"pattern\": \"^\/unleashed\" }")
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"4\", \"pattern\": \"^\/abc4000\" }")
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"5\", \"pattern\": \"^\/cm\" }")
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"6\", \"pattern\": \"^\/.*_vip\" }")

    end


    let(:config) do <<-CONFIG
      filter {
        urlgrok {
          patterns_dir => "#{tmpfile_path}"          
        }
      }
    CONFIG
    end
    
    sample "/news/code/test" do
      insist { subject["tags"] } == [ "URLGROK_1" ]
      insist { subject["category"] } == [ "news", "code" ]
    end

    sample "/cm/cb/4480226/Grandstand+iOS+icon+180x180/data.png" do
      insist { subject["tags"] } == [ "URLGROK_2" ]
      insist { subject["category"] } == [ "cm", "image" ]
    end
 
    sample "/news/cb/test" do
      insist { subject["tags"] } == [ "URLGROK_3" ]
      insist { subject["category"] } == [ "news", "cb" ]
    end

    sample "/news/contentblob/test" do
      insist { subject["tags"] } == [ "URLGROK_4" ]
      insist { subject["category"] } == [ "news", "contentblob" ]
    end

   sample "/news/feed/5342072/rss.xml" do
      insist { subject["tags"] } == [ "URLGROK_5" ]
      insist { subject["category"] } == [ "news", "feed" ]
    end

    sample "/news/studio/test" do
      insist { subject["tags"] } == [ "URLGROK_6" ]
      insist { subject["category"] } == [ "news", "studio" ]
    end

    sample "/cm/rimage/7002778-16x9-large.jpg?v=2" do
      insist { subject["tags"] } == [ "URLGROK_7" ]
      insist { subject["category"] } == [ "cm", "rimage" ]
      insist { subject["query"] } == "\"v=2\""
    end

    sample "/news/image/6999790-3x2-285x190.jpg" do
      insist { subject["tags"] } == [ "URLGROK_8" ]
      insist { subject["category"] } == [ "news", "image" ]
    end

    sample "/news/lb/test" do
      insist { subject["tags"] } == [ "URLGROK_9" ]
      insist { subject["category"] } == [ "news", "lb" ]
    end

    sample "/news/linkableblob/test" do
      insist { subject["tags"] } == [ "URLGROK_10" ]
      insist { subject["category"] } == [ "news", "linkableblob" ]
    end

    sample "/news/pagination/test/99999" do
      insist { subject["tags"] } == [ "URLGROK_11" ]
      insist { subject["category"] } == [ "news", "pagination" ]
    end

    sample "/news/service/test/99999" do
      insist { subject["tags"] } == [ "URLGROK_12" ]
      insist { subject["category"] } == [ "news", "service" ]
    end

    sample "/news/ajax/test" do
      insist { subject["tags"] } == [ "URLGROK_13" ]
      insist { subject["category"] } == [ "news", "ajax" ]
    end

    sample "/news/map/id=" do
      insist { subject["tags"] } == [ "URLGROK_14" ]
      insist { subject["category"] } == [ "news", "map" ]
    end

    sample "/news/map/" do
      insist { subject["tags"] } == [ "URLGROK_15" ]
      insist { subject["category"] } == [ "news", "map" ]
    end

    sample "/news/media/segment3/segment4" do
      insist { subject["tags"] } == [ "URLGROK_16" ]
      insist { subject["category"] } == [ "news", "media", "segment3", "segment4" ]
    end

    sample "/news/archive/segment3/" do
      insist { subject["tags"] } == [ "URLGROK_17" ]
      insist { subject["category"] } == [ "news", "archive", "segment3" ]
    end

    sample "/news/topics/segment3" do
      insist { subject["tags"] } == [ "URLGROK_18" ]
      insist { subject["category"] } == [ "news", "topics", "segment3" ]
    end

    sample "/news/topic/segment3" do
      insist { subject["tags"] } == [ "URLGROK_19" ]
      insist { subject["category"] } == [ "news", "topic", "segment3" ]
    end

    sample "/news/segment2/topic/segment4" do
      insist { subject["tags"] } == [ "URLGROK_20" ]
      insist { subject["category"] } == [ "news", "topic", "segment2", "segment4" ]
    end

    sample "/news/persontopic/segment3" do
      insist { subject["tags"] } == [ "URLGROK_21" ]
      insist { subject["category"] } == [ "news", "persontopic", "segment3" ]
    end

    sample "/news/bytopic/segment3" do
      insist { subject["tags"] } == [ "URLGROK_22" ]
      insist { subject["category"] } == [ "news", "bytopic", "segment3" ]
    end

    sample "/probe-vuncle2-cae01" do
      insist { subject["tags"] } == [ "URLGROK_23" ]
      insist { subject["category"] } == [ "probe-vuncle2-cae01", "probe" ]
    end

    sample "/news/2015-12-18/taxpayers-may-have-to-pay-clean-up-bill-for-victorian-coal-mines/7039898?WT.ac=statenews_vic" do
      insist { subject["tags"] } == [ "URLGROK_24" ]
      insist { subject["category"] } == [ "news", "detailed_page" ]
      insist { subject["query"] } == "\"WT.ac=statenews_vic\""
    end

    sample "/news/img" do
      insist { subject["tags"] } == [ "URLGROK_25" ]
      insist { subject["category"] } == [ "news", "image" ]
    end

    sample "/news/image" do
      insist { subject["tags"] } == [ "URLGROK_25" ]
      insist { subject["category"] } == [ "news", "image" ]
    end

    sample "/news/8686868" do
      insist { subject["tags"] } == [ "URLGROK_26" ]
      insist { subject["category"] } == [ "news", "cm_id_lookup" ]
    end

    sample "/radionational/warren-cahill/1234567" do
      insist { subject["tags"] } == [ "URLGROK_27" ]
      insist { subject["category"] } == [ "radionational", "person", "warren-cahill"]
    end

    sample "/radionational/programs/index=p" do
      insist { subject["tags"] } == [ "URLGROK_28" ]
      insist { subject["category"] } == [ "radionational", "index" ]
    end

    sample "/radionational/program/breakfast" do
      insist { subject["tags"] } == [ "URLGROK_30" ]
      insist { subject["category"] } == [ "radionational", "detailed_page", "breakfast" ]
    end

    sample "/radionational/subjects/music/?page=9" do
      insist { subject["tags"] } == [ "URLGROK_30" ]
      insist { subject["category"] } == [ "radionational", "detailed_page", "music" ]
    end

    sample "/radionational/6674412/competitions-2015/terms-and-conditions/6873620" do
      insist { subject["tags"] } == [ "URLGROK_31" ]
      insist { subject["category"] } == [ "radionational", "competitions-2015" ]
    end

    sample "/rn/podcast/feeds/science.xml" do
      insist { subject["tags"] } == [ "URLGROK_32" ]
      insist { subject["category"] } == [ "rn", "podcast" ]
    end

    sample "/unleashed/stories/s2832472.htm" do
      insist { subject["tags"] } == [ "URLGROK_33" ]
      insist { subject["category"] } == [ "unleashed", "detailed_page", "stories" ]
    end

    sample "/unleashed/s2832472.htm" do
      insist { subject["tags"] } == [ "URLGROK_34" ]
      insist { subject["category"] } == [ "unleashed", "detailed_page" ]
    end

    sample "/news/stories/2009/10/25/2723473.htm" do
      insist { subject["tags"] } == [ "URLGROK_35" ]
      insist { subject["category"] } == [ "news", "landing_page", "stories" ]
    end

    sample "/news/scitech" do
      insist { subject["tags"] } == [ "URLGROK_35" ]
      insist { subject["category"] } == [ "news", "landing_page", "scitech" ]
    end

    sample "/news" do
      insist { subject["tags"] } == [ "URLGROK_36" ]
      insist { subject["category"] } == [ "news", "landing_page" ]
    end

    sample "/news/" do
      insist { subject["tags"] } == [ "URLGROK_37" ]
      insist { subject["category"] } == [ "news", "landing_page" ]
    end

  end
 
  describe "test no filters, no match" do

    let(:config) do <<-CONFIG
      filter {
        urlgrok {
        }
      }
    CONFIG
    end

    sample "/hello/this/is/a/test" do
      insist { subject["tags"] } == [ "_urlgrokparsefailure" ]
    end

  end


  describe "test input filter" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"type\": \"input\", \"patternkey\": \"1\", \"pattern\": \"^\/test\", \"category_tags\": { \"tag\": \"test\" } }")
    end

    let(:config) do <<-CONFIG
      filter {
        urlgrok {
          patterns_dir => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample "/hello/this/is/a/test" do
      insist { subject["tags"] } == [ "_urlgrokparsefailure" ]
    end

  end

  describe "test tag prefix" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"1\", \"pattern\": \"^\/test\", \"category_tags\": { \"tag\": \"test\" } }")
    end

    let(:config) do <<-CONFIG
      filter {
        urlgrok {
          tags_prefix => "URLOK_"
          patterns_dir => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample "/test/a" do
      insist { subject["tags"] } == [ "URLOK_1" ]
      insist { subject["category"] } == [ "test" ]
    end

  end

  describe "http://ip/a/b/c" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"1\", \"pattern\": \"^\/test\", \"category_tags\": { \"tag\": \"test\" } }")
    end

    let(:config) do <<-CONFIG
      filter {
        urlgrok {
          patterns_dir => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample "http://10.0.0.1/test/a" do
      insist { subject["tags"] } == [ "URLGROK_1" ]
      insist { subject["category"] } == [ "test" ]
    end

  end

  describe "no data in event[@match]" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"type\": \"output\", \"patternkey\": \"1\", \"pattern\": \"^\/test\", \"category_tags\": { \"tag\": \"test\" } }")
    end

    let(:config) do <<-CONFIG
      filter {
        urlgrok {
          patterns_dir => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample "" do
      insist { subject["tags"] }.nil?
    end

  end


end
