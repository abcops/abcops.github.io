# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/timestamp"
require "json"
require "date"

class LogStash::Filters::VarnishLog < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   varnishlog {
  #      param_list => { "Request" => { "ReqHeader" => { "X-Akamai-Edgescape" => [ ",", "=" ] "Cookie" => [ "=" ]  } } }
  #   }
  # }
  #
  config_name "varnishlog"

  # Parameters can be passed as hash
  config :param_list, :validate => :hash, :default => {}

  public
  def register

    @reqheaderHash = Hash.new

    # validate paaram lit that they can only have max of 2 delimeters
    @param_list.each do |k,v|

      if v.size() > 2
        @param_list.remove(k)
        @logger.error("logstash-filter-varnishlog: Parameter #{k} as greater than 2 parameters =(#{k.size()}")
      end
      
    end

  end # def register

  public
  def filter(event)

    parse_event(event)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end # def filter


  private
  def parse_event(event)

    begin
      messageType = event['message'].gsub("\n","").gsub(/  >>.+/ , "").gsub("*   << ", "").gsub(" ", "")
    rescue
      @logger.error("logstash-filter-varnishlog: Unable to parse message header.")
      event.cancel
    end

    if @param_list.has_key?(messageType)

      event['message_type'] = messageType
      eventList = @param_list[messageType]

      # if flags are set true we pass the event
      listUpdate=false
      keyFound=false

      messageList = event['message'].split("\n")
      messageList.each do |item|

        if item =~ /^-\s+Timestamp/

          begin

            # -   Timestamp      Start: 1452319356.324483 0.000000 0.000000
            data=item.gsub("-   Timestamp      ","").split(":")
            timestamp = data[1].lstrip.split(" ")
            event['timestamp'] ||= {}
            event['timestamp'][data[0]] = DateTime.strptime(timestamp[0],"%s").to_time
            # Use the Start timestamp as the @timestamp
            if data[0] == "Start"
              # convert to millisecond epoch
              eventTimestamp = timestamp[0].to_f
              event['@timestamp'] = LogStash::Timestamp.at(eventTimestamp, (eventTimestamp % 1) * 1000000)
            end

          rescue
            @logger.error("logstash-filter-varnishlog: Unable to parse timestamp { message_type=#{message_type} message_segment=#{item} timestamp=#{timestamp} }")
          end

        else
          begin

            eventDetail = Array.new

            # Find nested parameters
            # -   ReqHeader      X-Akamai-CONFIG-LOG-DETAIL: true
            #     eventDetail[0]   eventDetail[1]          : eventValue
            if item.count(':') > 0

              data = item.gsub(/^-\s+/,"").split(":")
              eventDetail = data[0].split(" ")
              eventValue = ""

              if data.size() > 1
                eventValue = data[1].gsub(" ","")
              end

            else

              # -   Begin          req 294491835 rxreq
              # -   BereqMethod    GET
              data = item.gsub(/^-\s+/,"").split(" ")
              eventDetail << data[0]
              eventValue = data.drop(1).join(" ")

            end

          rescue
            @logger.error("logstash-filter-varnishlog: Unable to parse request { message_type=#{message_type} message_segment=#{item} }")
          end

          # Store Request header information
          if eventDetail[0] == "ReqHeader"

            if !@reqheaderHash.has_key?(eventDetail[1])

              @reqheaderHash[eventDetail[1]] = eventDetail[1]
              event['request_header'] ||= []
              event['request_header'] << eventDetail[1] unless event['request_header'].include?(eventDetail[1])
              listUpdate=true

            end

          end

          if eventList.has_key?(eventDetail[0])

            if eventList[eventDetail[0]].instance_of?(Hash)

              if eventList[eventDetail[0]].has_key?(eventDetail[1])

                event[eventDetail[0]] ||= {}
                event[eventDetail[0]][eventDetail[1]] ||= {}
                event[eventDetail[0]][eventDetail[1]]['raw'] = eventValue

                # parse_message_vales(event, messageEvent, messageTag, messageValue, delimeters)
                parse_message_vales(event, eventDetail[0], eventDetail[1], eventValue, eventList[eventDetail[0]][eventDetail[1]])

                keyFound=true
              end

            else

              event[eventDetail[0]] ||= {}
              event[eventDetail[0]] = eventValue

            end
          end
        end
      end
      
      # if dont get any valida information cancel the event
      if !listUpdate and !keyFound
        event.cancel
      end
      
      # Remove the message data
      event.remove('message')

    else
      event.cancel
    end
    
  end

  private
  def parse_message_vales(event, messageEvent, messageTag, messageValue, delimeters)

    data = messageValue.split( delimeters[0] )

    if delimeters.size == 2
      data = messageValue.split( delimeters[0] )
      delimeters=delimeters.drop(1)
      data.each do |i|
          parse_message_vales(event, messageEvent, messageTag, i, delimeters)
      end
    elsif delimeters.size == 1
      get_geopoint_data(event, messageTag, data)
      event[messageEvent][messageTag][data[0]] = data[1]
    end

  end

  private
  def get_geopoint_data(event, messageTag, messageValue)

    if messageTag == "X-Akamai-Edgescape"
      if messageValue[0] == 'lat'
        event['geoip'] ||= {}
        event['geoip']['location'] ||= []
        event['geoip']['latitude'] = messageValue[1].to_f
      elsif messageValue[0] == 'long'
        event['geoip']['longitude'] = messageValue[1].to_f
        event['geoip']['location'] ||= []
        event['geoip']['location'] = [ event['geoip']['longitude'], event['geoip']['latitude'] ]
      end
    end

  end

  private
  def param_test()
    @param_list1.each do |k,v|
      @logger.warn("Message #{k}")
      v.each do |k1,v1|
        @logger.warn("Message Event #{k1}")
        v1.each do |k2,v2|
          @logger.warn("Message Item #{k2}")
          v2.each do |i|
            @logger.warn("Delimiter #{i}")
          end
        end
      end
    end
  end

end # class LogStash::Filters::VarnishLog

