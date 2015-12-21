# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/environment"
require "set"
require "json"

# This class is used to validate fields defined after a reindex
class LogStash::Filters::UrlGrok < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   urlgrok {
  #     match => "message"
  #     tags_prefix => "URLGROK_"
  #     patterns_dir => "/pattern/location"
  #     tag_on_failure => [ "_urlgrokparsefailure" ]
  #   }
  # }
  #
  config_name "urlgrok"

  # The pattern file format is json format 
  #  @ type: input/output filter
  #    Whether the pattern is applied to the input or the output
  #  @ patternkey: 
  #    Key to indentify which filter was applied
  #  @ pattern
  #    regex pattern to apply
  #  @ category_tags
  #    tags to be attached to the event, seg "#" define an element with in the url
  #    example /www/test/url
  #    segemnt /1  /2   /3
  # { "type": "output", "patternkey": "1", "pattern": "^example", "category_tags": { "seg_<segment_location>": "category1", "tag": "category2" .... } }  

  # the event key that we will be parsing
  config :match, :validate => :string, :default => "message"

  # Prefix added to the patternkey which will be stored in the tags
  config :tags_prefix, :validate => :string, :default => "URLGROK_"

  # location of the pattern files
  config :patterns_dir, :validate => :array, :default => [ "/opt/logstash/urlpatterns" ]

  # Append values to the `tags` field when there has been no
  # successful match
  config :tag_on_failure, :validate => :array, :default => [ "_urlgrokparsefailure" ]
 
  public
  def register
  
    require "grok-pure" # rubygem 'jls-grok'

    # Store pattern files
    @patternfiles = []

    # Have @@patterns_path show first. Last-in pattern definitions win; this
    # will let folks redefine built-in patterns at runtime.
    @logger.info? and @logger.info("Grok patterns path", :patterns_dir => @patterns_dir)
    @patterns_dir.each do |path|
      if File.directory?(path)
        path = File.join(path, "*")
      end
  
      Dir.glob(path).each do |file|
        @logger.info? and @logger.info("Grok loading patterns from file", :path => file)
        @patternfiles << file
      end
    end

    @output_filter_hash = Hash.new 
    @input_filter_hash = Hash.new 

    add_patterns_from_files(@patternfiles, @input_filter_hash, @output_filter_hash)

  end # def register

  public
  def filter(event)

    # if we have no data in the match string dont attempt to filter
    if defined?(event[@match]).nil?
      @logger.info("No valid data in event[#{@match}]")
      return
    end

    # if the request is in the format http://10.0.10.1
    event[@match] = event[@match].sub(/^https?\:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/, '')

    # Attempt to find the patterns from a malformed url
    # example http://test/a/bhttp://test/b
    # else attempt to split on ? to collect any query parameters
    if event[@match] =~ /http/
      eventarr = event[@match].split("http")
    else
      eventarr = event[@match].split("?")
    end

    if eventarr.size() >= 1

      urlarr = eventarr[0].split("/")

      if check_input_filter(event)  

        event["category"] ||= [] 
        event["category"] << urlarr[1] unless event["category"].include?(urlarr[1])

        key = get_category_tags(event, urlarr)
        if not key.nil?
           event["tags"] ||= []
           event["tags"] << "#{@tags_prefix}#{key}" unless event["tags"].include?("#{@tags_prefix}#{key}")
           @logger.info("pattern match? key=URLGROK_#{key}") 
        else
           @logger.info("pattern match? nil")
           add_error_tags(event)
        end

        # if have a second part the url confirm it is a query component
        if eventarr.size() == 2 and eventarr[1] !~ /^:/
          event["query"] = "\"#{String(eventarr[1])}\""
        end

      end
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter


  private
  def get_category_tags(event, urlarr)
    @output_filter_hash.each do |k,v|
      if match(event[@match], v["pattern"])
        add_category(event, v['category_tags'], urlarr)
        return k
      end
    end
    return nil
  end

  private
  def check_input_filter(event)
    if @input_filter_has.nil? 
      return true
    end
    @input_filter_hash.each do |k,v|
      return match(event[@match], v['pattern'])
      @logger.info("Input pattern found key=#{k}")
    end
    @logger.info("Input pattern not found, message ignored")
    return false
  end

  private
  def match(input, pattern)
    if input =~ /#{pattern}/
       return true
    end
    return false
  end


  private
  def add_category(event, category_tags, urlarr)
    category_tags.each do |k,v|
      if k == "tag"
        event['category'] << v unless event['category'].include?(v)
      elsif k =~ /^seg/
        event['category'] << urlarr[v.to_i] #unless event['category'].include?(urlarr[v.to_i])
      else
        @logger.info("Invalid category tag")
      end
    end
  end


  private
  def add_patterns_from_files(paths, input_filter, output_filter)
    count=0
    paths.each do |path|
      if !File.exists?(path)
        raise "URL Grok pattern file does not exist: #{path}"
      end
      file = File.read(path)
      file.each_line do |line|
        json_line = JSON.parse(line)
        if json_line['type'] == "input"
          input_filter[json_line['patternkey']] = json_line
          @logger.info("Pattern file input filter element: ", json_line)
        elsif json_line['type'] == "output"
          output_filter[json_line['patternkey']] = json_line
          @logger.info("Pattern file output filter element: ", json_line)
        else
          @logger.info("Unknown pattern type valid values input/output: ", json_line)
        end
      end
    end
  end # def add_patterns_from_files

  private
  def add_error_tags(event)
    @tag_on_failure.each do |tag|
      event["tags"] ||= []
      event["tags"] << tag unless event["tags"].include?(tag)
    end
  end

end # class LogStash::Filters::UrlGrok
