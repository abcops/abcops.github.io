# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require "json"

# This class is used to validate fields defined after a reindex
class LogStash::Filters::Validate < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   validate {
  #     validate_file => "/opt/logstash/validate/validate.out"
  #     target => "message"
  #     tag_on_failure => "_validationerror"
  #     tag_on_success => "_validationsuccessful"
  #     debug => true
  #   }
  # }
  #
  config_name "validate"
  
  # define the location of the validate file
  config :validate_file, :validate => :string, :default => "/opt/logstash/validate/validate.out"

  # the event key that we will be parsing
  config :target, :validate => :string, :default => "message"

  # Append values to the `tags` field when there has been no
  # validation failure
  config :tag_on_failure, :validate => :string

  # Append values to the `tags` field when there has been no
  # validation successful
  config :tag_on_success, :validate => :string
  
  # add error code to tags
  config :debug, :validate => :boolean, :default => false


  module ERRCODE
    NOKEYFOUNDERR=1
    NONACCESSPARSEERR=2
    REDZONEERR=4
    BLUEZONEERR=8
    ACCESSPARSEERR=16
    NOVALIDDATAERR=32
  end

  public
  def register

    # hash that will store the validation data
    @keyhash = Hash.new

    load_validate_file()

    @logger.debug("validate_file", @keyhash)

    if @keyhash.empty?
      @logger.error("Unable to parse validation file")
    end

  end # def register

  public
  def filter(event)

    errorflag=0

    begin
      path = event[@target].sub(/\.[0-9]{4}-[0-9]{2}-[0-9]{2}/, "")
      getjson = @keyhash[path]

      if getjson.nil?
        errorflag=errorflag|ERRCODE::NOKEYFOUNDERR
        @logger.error("errorcode=#{errorflag} key does not exists in #{@validate_file} #{event[path]}")
      else
        getjson.each do |k,v|
          if event["type"] !~ /access[.-]log/ and event["type"] !~ /error[.-]log/ and event["type"] !~ /varnishncsa.log/
            if k != "host"
              if event[k] != v
                errorflag=errorflag|ERRCODE::NONACCESSPARSEERR
                debug && @logger.warn? && @logger.warn("errorcode=#{errorflag} key=#{k} event[#{k}]=#{event[k]} value=#{v}")
              end
            end
          else
            if k != "type" and k != "host"
              if k == "zone"
                if event["host"] =~ /^inw/
                  if event["zone"] != "red"
                    errorflag=errorflag|ERRCODE::REDZONEERR
                    debug && @logger.warn? && @logger.warn("errorcode=#{errorflag} host=#{event['host']} zone=#{event['zone']}")
                  end
                elsif event["host"] =~ /^nuc/
                  if event["zone"] != "blue"
                    errorflag=errorflag|ERRCODE::BLUEZONEERR
                    debug && @logger.warn? && @logger.warn("errorcode=#{errorflag} host=#{event['host']} zone=#{event['zone']}")
                  end
                end
              else
                if k == "path"
                  if path != v
                    errorflag=errorflag|ERRCODE::ACCESSPARSEERR
                    debug && @logger.warn? && @logger.warn("errorcode=#{errorflag} key=#{k} event[#{k}]=#{path} value=#{v}")
                  end
                else
                  if event[k] != v
                    errorflag=errorflag|ERRCODE::ACCESSPARSEERR
                    debug && @logger.warn? && @logger.warn("errorcode=#{errorflag} key=#{k} event[#{k}]=#{event[k]} value=#{v}")
                  end
                end
              end
            end
          end
        end
      end
    rescue
      debug && @logger.warn("Unable to determine valid data #{path}")
      errorflag=errorflag|ERRCODE::NOVALIDDATAERR
    end
        
    if errorflag > 0
      if !@tag_on_failure.nil?
        event["tags"] ||= []
        event["tags"] << @tag_on_failure unless event["tags"].include?(@tag_on_failure)
      end
      if debug
         event["tags"] ||= []
         event["tags"] << "_errorcode_" + errorflag.to_s unless event["tags"].include?("_errorcode_" + errorflag.to_s)
      end
    else
      if !@tag_on_success.nil?
        event["tags"] ||= []
        event["tags"] << @tag_on_success unless event["tags"].include?(@tag_on_success)
      end
    end
 
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  private
    def load_validate_file()
      begin
        file = File.read(@validate_file)
        file.each_line do |line|
          json_line = JSON.parse(line)
          json_line["path"] = json_line["path"].sub(/\.\%\{\+YYYY-MM-dd\}/, "")
          json_line["path"] = json_line["path"].sub(/\.\*/, "")
          @keyhash[json_line["path"]] = json_line
        end
      rescue StandardError => e
        @logger.error("load_validate_file threw exception", :exception => e.message)
      end
    end

end # class LogStash::Filters::Validate
