require 'rubygems'
require 'resolv'
require 'metaid'
HoneyResponse = Struct.new(:status, :days, :threat, :type)

access_key = ARGV[0]

infos = Hash.new
bad_guys = Hash.new
File.open('access.log') do |f|
  f.each do |line|
  	ip = line.split(/\s/)[0]

	if infos[ip]
	  info = infos[ip]
	else
	  octets = ip.split('.').reverse.join('.')
	  dns_name = "#{access_key}.#{octets}.dnsbl.httpbl.org"
	  response = Resolv.getaddress dns_name
	  raw_info = response.split('.').map(&:to_i)
	  info = HoneyResponse.new(*raw_info)
	  infos[ip] = info
	end

	meta_def(:report) do |string|
	  puts "#{string} at #{ip}, got #{info.inspect}\t#{line}"
	end
	
	if( info.status != 127)
	  #puts "Some sort of error resolving #{dns_name}, got #{response}"
	  next
	end
	if( info.days > 31 )
	  report "Stale info"
	  next
	end
	if( info.type == 0 )
	  #puts "Search engine at #{ip}, got #{info.inspect}"
	  next
	end
	if( info.type == 1 )
	  report "Suspicious only"
	  next
	end
	if( info.threat < 5 )
	  report "Low threat"
	  next
	end
	report "Bad guy"
	bad_guys[ip] = true

  end
end

bad_guys.keys.each do |ip|
  puts "banning #{ip}"
  print ` iptables -D INPUT -s 194.165.42.59 -j REJECT 2> /dev/null`
  print ` iptables -A INPUT -s 194.165.42.59 -j REJECT `
  print `iptables -L`
end
