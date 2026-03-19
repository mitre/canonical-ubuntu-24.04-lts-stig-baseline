control 'SV-270709' do
  title 'Ubuntu 24.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', 'Verify the SSH daemon prevents remote hosts from connecting to the proxy display with the following command:

$ sudo grep -ir x11uselocalhost /etc/ssh/sshd_config*
X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is commented out, is missing, or multiple conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to prevent remote hosts from connecting to the proxy display.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11UseLocalhost" keyword and set its value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11UseLocalhost yes

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-270709'
  tag rid: 'SV-270709r1066616_rule'
  tag stig_id: 'UBTU-24-300023'
  tag fix_id: 'F-74643r1066615_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(%w[docker podman kubepods lxc].include?(virtualization.system) && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('X11UseLocalhost') { should cmp 'yes' }
  end
end
