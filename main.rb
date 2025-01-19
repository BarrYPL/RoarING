require 'csv'
require 'uri'
require 'time'
require 'cgi'
require 'levenshtein'

# Function to decode URL parameters considering UTF-8 encoding
def decode_with_utf8(params)
  CGI.unescape(params.to_s).force_encoding("UTF-8")
end

# Function to parse URL query parameters into a hash
def parse_query_params(params)
  params = CGI.escape(params.to_s)
  return {} if params.strip.empty?
  URI.decode_www_form(params.to_s).map { |k, v| [k, nil] }.to_h
end

# Function to clean parameters, keeping only the keys, ignoring the values
def clean_params(params)
  params = params.keys
  params = remove_polish_chars(params.first)
  if params.is_a?(String)
    unescaped_params = CGI.unescape(params)
    return URI.decode_www_form(unescaped_params).map { |k, _| k }.uniq
  elsif params.is_a?(Hash)
    return params.keys
  else
    return []
  end
end

# Function to clean the endpoint, removing the transaction identifier after the comma
def clean_endpoint(endpoint)
  # Remove everything after the first comma, if it exists
  endpoint.gsub(/,.*$/, '')
end

# Normalize parameters by sorting the keys before adding them
def normalize_params(params)
  params.sort
end

def average(array)
  return 0 if array.empty?  # Prevent division by zero
  array.sum.to_f / array.size
end

def sql_injection_detection(query)
  query = query.first.to_s
  return false unless query.is_a?(String)

  patterns = [
    { pattern: /(select|union|insert|update|delete|drop)/i, description: 'SQL keywords (SELECT, UNION, INSERT, etc.)' },
    { pattern: /or\s+\d+=\d+/i, description: 'OR 1=1, OR 2=2, etc.' },
    { pattern: /or\s+\'\d\'=\'\d\'/i, description: "OR '1'='1', OR '2'='2', etc." },
    { pattern: /\band\b\s+\d+=\d+/i, description: 'AND 1=1' },
    { pattern: /waitfor\s+delay/i, description: 'WAITFOR DELAY' },
    { pattern: /(\%27|\'|\%23|#)/i, description: 'URL encoding (apostrophes, comments)' },
    { pattern: /\blike\b/i, description: 'LIKE keyword' },
    { pattern: /(\%3B|;)/i, description: 'Semicolon (end of statement)' },
    { pattern: /(\%2F|\/\*|\*\/|\%2A)/i, description: 'SQL comments' },
    { pattern: /\bxp_\w+/i, description: 'XP procedure calls (e.g. xp_cmdshell)' },
    { pattern: /\b(\d{1,4}(\.\d{1,2}){3})\b/i, description: 'IP address format' },
    { pattern: /(\%22|\"|\%5C|\\)/i, description: 'Quotes and backslash' },
    { pattern: /(\%0A|\%00|\%0D|\%09)/i, description: 'Newline, null byte, carriage return, tab' }
  ]

  patterns.each_with_index do |item, index|
    if query.match?(item[:pattern])
      return true
    end
  end

  false
end

# Class for managing sessions
class SessionManager
  def initialize(max_sessions = 10)
    @sessions = {}  # Hash storing sessions with the user's IP as key
    @user_session_stats = {}  # Store individual user session stats
    @max_sessions = max_sessions  # Maximum number of sessions to store
    @levenshtein_cache = {}
    @suspicious_ips = {}
    @suspicious_request_count = 0
  end

  def compare_user_agents(user_agent)
    names_to_compare = get_selected_stats(:user_agent)
    results = []

    names_to_compare.each do |existing_ua|
      existing_ua_string = existing_ua.keys.first
      count = existing_ua.values.first
      cache_key = [user_agent, existing_ua_string].sort.join('-')
      if @levenshtein_cache[cache_key]
        distance = @levenshtein_cache[cache_key]
      else
        distance = Levenshtein.distance(user_agent, existing_ua_string)
        @levenshtein_cache[cache_key] = distance
      end
      similarity = 1 - (distance.to_f / [user_agent.length, existing_ua_string.length].max)
      weighted_similarity = similarity * count
      results << weighted_similarity
    end
    average_similarity = results.sum / results.size
    average_similarity <= 2.8
  end

  # Add a new session and update stats
  def add_session(ip, session_data)
    @sessions[ip] ||= []
    @user_session_stats[ip] ||= {
      method: Hash.new(0),
      path: Hash.new(0),
      params: Hash.new(0),
      timestamp: Hash.new(0),
      referrer: Hash.new(0),
      user_agent: Hash.new(0),
      protocol: Hash.new(0),
      status: Hash.new(0),
      total_requests: 0,
      avg_time_gap: 0
    }

    # Add session data to sessions
    @sessions[ip].push(session_data)

    # Recalculate individual user stats after adding session
    update_user_session_stats(ip, session_data)

    # Recalculate average time gap and total requests after adding a new session
    update_user_session_avg(ip)

    # Remove oldest session if size exceeds max_sessions
    if @sessions[ip].size > @max_sessions
      @sessions[ip].shift
      # Recalculate stats after removing the session
      recalculate_user_session_stats(ip)
    end
  end

  # Function to update the statistics for the individual user's session
  def update_user_session_stats(ip, session_data)
    @user_session_stats[ip][:method][session_data[:method]] += 1
    @user_session_stats[ip][:path][session_data[:path]] += 1
    session_data[:params].each { |param| @user_session_stats[ip][:params][param] += 1 }
    @user_session_stats[ip][:timestamp][session_data[:timestamp].to_s] += 1
    @user_session_stats[ip][:referrer][session_data[:referrer]] += 1
    @user_session_stats[ip][:user_agent][session_data[:user_agent]] += 1
    @user_session_stats[ip][:protocol][session_data[:protocol]] += 1
    @user_session_stats[ip][:status][session_data[:status]] += 1
  end

  # Function to recalculate stats based on current session data for a specific user
  def recalculate_user_session_stats(ip)
    # Reset the user's session stats
    @user_session_stats[ip] = {
      method: Hash.new(0),
      path: Hash.new(0),
      params: Hash.new(0),
      timestamp: Hash.new(0),
      referrer: Hash.new(0),
      user_agent: Hash.new(0),
      protocol: Hash.new(0),
      status: Hash.new(0),
      total_requests: 0,
      avg_time_gap: 0
    }

    # Recalculate stats for all sessions of the user
    @sessions[ip].each do |session_data|
      update_user_session_stats(ip, session_data)
    end

    # Recalculate the average time gap and total requests
    update_user_session_avg(ip)
  end

  # Function to update average time gap and total requests for a user's session
  def update_user_session_avg(ip)
    timestamps = @sessions[ip].map { |session| session[:timestamp] }

    return if timestamps.size < 2

    # Sort timestamps to calculate time differences
    timestamps.sort!
    time_gaps = []

    # Calculate time differences between consecutive timestamps
    (1...timestamps.size).each do |i|
      time_gaps << (timestamps[i] - timestamps[i-1]).to_i
    end

    # Calculate the average time gap
    avg_time_gap = time_gaps.sum / time_gaps.size
    total_requests = timestamps.size

    # Update user's session stats
    @user_session_stats[ip][:avg_time_gap] = avg_time_gap
    @user_session_stats[ip][:total_requests] = total_requests
  end

  # Function to get the session statistics for a specific user (IP)
  def get_user_session_stats(ip)
    @user_session_stats[ip] || {}
  end

  # Function to print specific session stat (like time gap) for all sessions
  def get_selected_stats(stat_key = nil)
    if stat_key.nil?
      puts "Please specify a stat key (e.g. :avg_time_gap)."
      return
    end

    arr = []
    # Iterate over each IP session stats and print the selected stat
    @user_session_stats.each do |ip, stats|
      if stats[stat_key]
        arr << stats[stat_key]
      else
        puts "IP: #{ip} - #{stat_key.capitalize}: Not available"
      end
    end

    return arr
  end

  # Function to print session stats for the user (or all sessions) with specific keys
  def print_session_stats(ip = nil, stat_key = nil)
    if stat_key
      # Print selected stat for all sessions if stat_key is provided
      print_selected_stat(stat_key)
    else
      if ip.nil?
        @sessions.each do |ip|
          stats = @user_session_stats[ip.first]
          if stats
            print_individual_stats(stats)
          end
        end
      else
        stats = @user_session_stats[ip]
        if stats.nil?
          puts "No session data found for IP: #{ip}"
          return
        end
        print_individual_stats(stats)
      end
    end
  end

  # Helper function to print individual stats
  def print_individual_stats(stats)
    stats.each do |key, value|
      if value.is_a?(Hash)
        puts "#{key.capitalize}:"
        value.each do |sub_key, count|
          puts "  #{sub_key}: #{count}"
        end
      else
        puts "#{key.capitalize}: #{value}"
      end
    end
  end

  def compare_sessions(ip, session_data)
    #User-Agend based
    if compare_user_agents(session_data[:user_agent])
      puts "Podejrzany agent #{session_data[:user_agent]}, IP: #{ip} dodano do obserwowanych."
      @suspicious_request_count += 1
      if @suspicious_ips[ip]
        @suspicious_ips[ip] << session_data
      else
        @suspicious_ips[ip] = [session_data]
      end
      true
    end

    #Time based
    if @sessions[ip]
      grouped_by_second = @sessions[ip].group_by { |session| session[:timestamp] }
      grouped_by_second.each do |time, queries|
        if queries.size > 2 #Because of the redirect, there were many duplicated requests, so we are looking for more than two, which would be suspicious.
          @suspicious_request_count += 1
          puts "Podejrzane zapytania w tej samej sekundzie dla IP: #{ip} (#{queries.size} zapytania w czasie #{time})"
          @suspicious_ips[ip] ||= []
          @suspicious_ips[ip] += queries
          return true
        end
      end
    end

    # Params based
    if sql_injection_detection(session_data[:params])
      puts "Podejrzane zapytanie w parametrach dla IP: #{ip} - #{session_data[:params]}"
      @suspicious_request_count += 1
      if @suspicious_ips[ip]
        @suspicious_ips[ip] << session_data
      else
        @suspicious_ips[ip] = [session_data]
      end

      true
    else
      false
    end

    false
  end

  def puts_session_data
    #print_session_stats("82.135.12.201")
    #puts @sessions["82.135.12.201"]
    #print_session_stats
    returned_arr = get_selected_stats(:user_agent)
    #puts returned_arr.inspect
    #puts average(returned_arr)
  end

  def get_stats
    @suspicious_request_count
  end

  # Method to save suspicious queries to a text file (default file name is suspicious_output.txt)
  def save_suspicious_queries_to_file(file_path = 'suspicious_output.txt')
    # Open the file in write mode
    File.open(file_path, 'w') do |file|
      # Write header to the file
      file.puts("Wykryte podejrzane zapytania:")

      # Iterate through all suspicious IPs and their sessions
      @suspicious_ips.each do |ip, sessions|
        file.puts("\nIP Address: #{ip}")

        sessions.each do |session|
          # Write each suspicious session to the file in a more readable format
          file.puts("  Method: #{session[:method]}")
          file.puts("  Path: #{session[:path]}")
          file.puts("  Params: #{session[:params].join('&')}")
          file.puts("  Timestamp: #{session[:timestamp]}")
          file.puts("  Referrer: #{session[:referrer]}")
          file.puts("  User-Agent: #{session[:user_agent]}")
          file.puts("  Protocol: #{session[:protocol]}")
          file.puts("  Status: #{session[:status]}")
          file.puts("-" * 40) # Separator between sessions
        end
      end
    end
    puts "Podejrzane zapytania zostały zapisane do pliku: #{file_path}"
  end
end

# Function to detect anomalies in the requests
def detect_anomalies(logs, session_manager)
  anomalies = []

  logs.each do |log|
    date, time, ip, method, path, protocol, status, referrer, user_agent, params = log

    # Decode the query parameters into key-value pairs
    query_params = decode_with_utf8(params)
    parsed_params = parse_query_params(query_params)
    timestamp = Time.parse("#{date} #{time}")

    # Create session data (only keys of params matter here)
    session_data = {
      method: method,
      path: path,
      params: parsed_params.keys,  # Only keep keys, not values
      timestamp: timestamp,
      referrer: referrer,
      user_agent: user_agent,
      protocol: protocol,
      status: status
    }

    # Check if the session is already recorded and detect anomalies
    if session_manager.compare_sessions(ip, session_data)
      anomalies << [ip, session_data]
    else
      session_manager.add_session(ip, session_data)
    end
  end

  puts anomalies
  anomalies
end

# Function to load logs from a CSV file
def load_logs(file, lines_to_load = nil, offset = 0)
  logs = []
  CSV.foreach(file, headers: false).with_index do |row, index|
    next if index < offset
    break if lines_to_load && index >= offset + lines_to_load
    logs << row
  end

  logs
end


# Main function
def check_logs
  file = 'logs.csv'  # Path to the log file
  learning_data_size = 100  # Set the learning data size
  max_sessions = 10

  # Load the learning data (first N records)
  learning_logs = load_logs(file, lines_to_load = learning_data_size)

  session_manager = SessionManager.new(max_sessions)  # Limit for stored sessions

  # Process the learning data and add them to the session manager
  learning_logs.each do |log|
    date, time, ip, method, path, protocol, status, referrer, user_agent, params = log
    query_params = decode_with_utf8(params)
    parsed_params = parse_query_params(query_params)
    timestamp = Time.parse("#{date} #{time}")
    session_data = {
      method: method,
      path: path,
      params: parsed_params.keys,  # Only keep keys, not values
      timestamp: timestamp,
      referrer: referrer,
      user_agent: user_agent,
      protocol: protocol,
      status: status
    }
    session_manager.add_session(ip, session_data)
  end

  ####################################
  # End of initial learning process  #
  # ##################################

  # Load the remaining logs starting from the learning data size
  logs = load_logs(file, lines_to_load = nil, offset = learning_data_size)  # Load all logs if necessary
  anomalies = detect_anomalies(logs, session_manager)

  # Print anomalies from anomalies array
  if anomalies.any?
    puts "Found anomalies:"
    anomalies.each { |anomaly| puts anomaly }
  end

  puts "Wykryte podejrzane zapytania: #{session_manager.get_stats}"

  session_manager.save_suspicious_queries_to_file
end

# Run the log check
check_logs
