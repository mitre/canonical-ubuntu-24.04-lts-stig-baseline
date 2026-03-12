control 'SV-270751' do
  title 'Ubuntu 24.04 LTS must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate. 
 
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 
 
Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Note: If the system is not networked, this requirement is not applicable.

Verify Ubuntu 24.04 LTS is configured to compare the system clock at least every 24 hours to an authoritative time source with the following command:

$ sudo grep -ir maxpoll /etc/chrony*
server [source] iburst maxpoll 16

If the parameter "server" is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.

If the "maxpoll" option is set to a number greater than 16, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'To configure the system clock to compare to the authoritative time source at least every 24 hours, edit the "/etc/chrony/chrony.conf" file. Add or correct the following lines, by replacing "[source]" in the following line with an authoritative time source: 

server [source] iburst maxpoll 16 

If the "chrony" service was running and the value of "maxpoll" or "server" was updated, the service must be restarted using the following command: 

$ sudo systemctl restart chrony.service'
  impact 0.3
  tag check_id: 'C-74784r1066740_chk'
  tag severity: 'low'
  tag gid: 'V-270751'
  tag rid: 'SV-270751r1066742_rule'
  tag stig_id: 'UBTU-24-600160'
  tag gtitle: 'SRG-OS-000785-GPOS-00250'
  tag fix_id: 'F-74685r1066741_fix'
  tag satisfies: ['SRG-OS-000785-GPOS-00250', 'SRG-OS-000355-GPOS-00143']
  tag 'documentable'
  tag cci: ['CCI-004922', 'CCI-004923']
  tag nist: ['SC-45', 'SC-45 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  time_sources = ntp_conf('/etc/chrony.conf').server

  # Cover case when a single server is defined and resource returns a string and not an array
  time_sources = [time_sources] if time_sources.is_a? String

  unless time_sources.nil?
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }
  end

  # Verify the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:

  describe ntp_conf('/etc/chrony.conf') do
    its('server') { should_not be_nil }
  end

  unless ntp_conf('/etc/chrony.conf').server.nil?
    if ntp_conf('/etc/chrony.conf').server.is_a? String
      describe ntp_conf('/etc/chrony.conf') do
        its('server') { should match input('authoritative_timeserver') }
      end
    end

    if ntp_conf('/etc/chrony.conf').server.is_a? Array
      describe ntp_conf('/etc/chrony.conf') do
        its('server.join') { should match input('authoritative_timeserver') }
      end
    end
  end
  # All time sources must contain valid maxpoll entries
  unless time_sources.nil?
    describe 'chronyd maxpoll values (99=maxpoll absent)' do
      subject { max_poll_values }
      it { should all be < 17 }
    end
  end
end
