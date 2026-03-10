control 'SV-270752' do
  title 'Ubuntu 24.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 
 
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). 
 
Organizations must also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done to determine the time difference.'
  desc 'check', 'Verify Ubuntu 24.04 LTS synchronizes internal system clocks to the authoritative time source when the time difference is greater than one second. 
 
Check the value of "makestep" with the following command: 
 
$ grep makestep /etc/chrony/chrony.conf
makestep 1 -1 
 
If the makestep option is not set to "1 -1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure chrony to synchronize the internal system clocks to the authoritative source when the time difference is greater than one second by doing the following:

Edit the "/etc/chrony/chrony.conf" file and add:

     makestep 1 -1

Restart the chrony service:

     $ sudo systemctl restart chrony.service'
  impact 0.3
  tag check_id: 'C-74785r1068364_chk'
  tag severity: 'low'
  tag gid: 'V-270752'
  tag rid: 'SV-270752r1068365_rule'
  tag stig_id: 'UBTU-24-600180'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-74686r1066744_fix'
  tag 'documentable'
  tag cci: ['CCI-002046', 'CCI-004926']
  tag nist: ['AU-8 (1) (b)', 'SC-45 (1) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  file_path = input('chrony_config_file')
  found_file = file(file_path)

  if found_file.exist?
    describe found_file do
      subject { found_file }
      its('content') { should match(/^\s*makestep\s+1\s+-1/) }
    end
    timedatectl = command('timedatectl').stdout
    describe 'NTP and clock synchronization' do
      it 'should have NTP service active' do
        expect(timedatectl).to match(/NTP service:\s*(active|enabled)/i)
      end
      it 'should have system clock synchronized' do
        expect(timedatectl).to match(/System clock synchronized:\s*yes/i)
      end
    end
  else
    describe("#{file_path} exists") do
      subject { found_file.exist? }
      it { should be true }
    end
  end
end
