control 'SV-274871' do
  title 'Ubuntu 24.04 LTS must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'Setting the screensaver mode to blank-only conceals the contents of the display from passersby.'
  desc 'check', 'Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

To verify the screensaver is configured to be blank, run the following command:

$ gsettings writable org.gnome.desktop.screensaver picture-uri

false

If "picture-uri" is writable and the result is "true", this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to prevent a user from overriding the picture-uri setting for graphical user interfaces.

In the file "/etc/dconf/db/local.d/00-security-settings", add or update the following lines:

[org/gnome/desktop/screensaver]
picture-uri=''

Prevent user modification by adding the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock":

/org/gnome/desktop/screensaver/picture-uri

Update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  tag check_id: 'C-78972r1107301_chk'
  tag severity: 'medium'
  tag gid: 'V-274871'
  tag rid: 'SV-274871r1107302_rule'
  tag stig_id: 'UBTU-24-200043'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-78877r1101765_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if package('gnome-shell').installed?
    describe file('/etc/dconf/db/local.d/00-security-settings') do
      its('content') { should match %r{^\[org/gnome/desktop/screensaver\]\npicture-uri=''\s*$} }
    end
    describe file('/etc/dconf/db/local.d/locks/00-security-settings-lock') do
      its('content') { should match %r{/org/gnome/desktop/screensaver/picture-uri} }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
