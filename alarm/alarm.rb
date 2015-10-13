require 'packetfu'


def help()
    puts "Usage: ruby #{__FILE__} [filename] \n"
end

def main(argv)
    i = 0
    while i < argv.length
        case argv[i]
        when "-h"
            help
            return        
        else
            File.open(argv[i], "r") do |f| analyze_log f end
            return
        end
        i += 1
    end
    analyze_stream
end


$num_incidents = 1
def report_incident(type, source, protocol, payload)
    #payload = payload.each_byte.map { |b| sprintf("0x%02X ",b) }.join
    puts "#{$num_incidents}. ALERT: #{type} is detected from #{source}" +
        " (#{protocol}) (#{payload})!\n"
    $num_incidents += 1
end


def is_null_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.empty?
end

def is_fin_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.length == 1 and flags.fin != 0
end

def is_xmas_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.length == 3 and
        flags.fin != 0 and flags.psh != 0 and flags.urg != 0
end

def is_nmap_scan?(packet)
    packet.payload.scan("\x4E\x6D\x61\x70").length > 0
end

def is_nikto_scan?(packet)
    packet.payload.scan("Nikto").length > 0
end

def is_credit_card_leak?(packet)
    packet.payload =~ /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
    packet.payload =~ /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
    packet.payload =~ /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
    packet.payload =~ /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
end

def analyze_stream()
    stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    stream.stream.each do |raw_data|
        packet = PacketFu::Packet.parse raw_data
        if packet.class == PacketFu::TCPPacket
            if is_null_scan? packet
                report_incident("NULL scan", packet.ip_saddr, "TCP", packet.payload)
            elsif is_fin_scan? packet
                report_incident("FIN scan", packet.ip_saddr, "TCP", packet.payload)
            elsif is_xmas_scan? packet
                report_incident("XMAS scan", packet.ip_saddr, "TCP", packet.payload)
            elsif is_nmap_scan? packet
                report_incident("Nmap scan", packet.ip_saddr, "TCP", packet.payload)
            elsif is_nikto_scan? packet
                report_incident("Nikto scan", packet.ip_saddr, "TCP", packet.payload)
            elsif is_credit_card_leak? packet
                report_incident("Credit card leak", packet.saddr, "HTTP", packet.payload)
            else
                
            end
        elsif packet.class == PacketFu::IPPacket

        elsif packet.class == PacketFu::UDPPacket

        elsif packet.class == PacketFu::EthPacket

        end
    end
end


def analyze_log(log)
    log.each_line do |line|
        regex = /(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\[.*?\])\s+(".*?")\s+(\d+)\s+(\d+)\s+("\S+")\s+(".*?")/
        match = regex.match(line)
        if match
            request = match[9]
            ip = match[1]
            match.captures.each do |m|
                if m.scan("phpmyadmin").length > 0
                    report_incident("phpmyadmin violation", ip, "HTTP", m)
                elsif m.scan(/(\\x0?...?){10,}/).length > 0
                    report_incident("Potential shellcode", ip, "HTTP", m)
                elsif m.scan("Nmap").length > 0
                    #report_incident("Nmap scan", ip, "HTTP", request)
                elsif m.scan("nikto").length > 0
                    report_incident("Nikto scan", ip, "HTTP", request)
                elsif m.scan("masscan").length > 0
                    report_incident("masscan", ip, "HTTP", m)
                end
            end
        end
    end
end


if __FILE__ == $0
    main(ARGV)
end

