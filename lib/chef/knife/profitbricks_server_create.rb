require 'chef/knife'
require 'chef/json_compat'
#require 'net/scp'
require 'fileutils'
require_relative 'profitbricks_base'

class Chef
  class Knife
    class ProfitbricksServerCreate < Knife

      deps do
        require 'net/ssh'
        require 'net/ssh/multi'
        require 'profitbricks'
        require 'highline'
        require 'chef/knife/bootstrap'
        require 'chef/knife/core/bootstrap_context'
        require 'securerandom'
        require 'timeout'
        require 'socket'

        Chef::Knife.load_deps

      end
      include Knife::ProfitbricksBase

      banner "knife profitbricks server create OPTIONS"

      option :datacenter_name,
        :short => "-D DATACENTER_NAME",
        :long => "--data-center DATACENTER_NAME",
        :description => "The datacenter where the server will be created",
        :proc => Proc.new { |datacenter| Chef::Config[:knife][:profitbricks_datacenter] = datacenter }

      option :name,
        :long => "--name SERVER_NAME",
        :description => "name for the newly created Server",
        :proc => Proc.new { |image| Chef::Config[:knife][:profitbricks_server_name] = image }

      option :memory,
        :long => "--ram RAM",
        :description => "Amount of Memory in MB of the new Server",
        :proc => Proc.new { |memory| Chef::Config[:knife][:profitbricks_memory] = memory }

      option :cpus,
        :long => "--cpus CPUS",
        :description => "Amount of CPUs of the new Server",
        :proc => Proc.new { |cpus| Chef::Config[:knife][:profitbricks_cpus] = cpus }

      option :lan_id,
        :short => "-L LAN_ID",
        :long => "--lan_id LAN_ID",
        :description => "This is the Profitbricks LAN_ID if you have more than one LAN",
        :proc => Proc.new { |lan_id| Chef::Config[:knife][:profitbricks_lan_id] = lan_id }

      option :wan_id,
        :short => "-W WAN_ID",
        :long => "--wan_id WAN_ID",
        :description => "This is the Profitbricks WAN_ID for accesing the internet",
        :proc => Proc.new { |wan_id| Chef::Config[:knife][:profitbricks_wan_id] = wan_id }

      option :private_ip,
        :short => "-IP PRIVATE_IP",
        :long => "--private_ip PRIVATE_IP",
        :description => "Private IPS must be in LANs 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16",
        :proc => Proc.new { |private_ip| Chef::Config[:knife][:profitbricks_private_ip] = private_ip }

      option :hdd_size,
        :long => "--hdd-size GB",
        :description => "Size of storage in GB, if activate, will be create the HDD additionaly",
        :default => "25"

      option :dhcpActive,
        :long => "--dhcpActive true/false",
        :description => "Profitbricks DHCP Server activate",
        :default => false

      option :activate_gateway_ip,
        :short => "-G GATEWAY_IP",
        :long => "--activate-gateway IP",
        :description => "Profitbricks DHCP Server activate as a IP Adress"

      option :bootstrap,
        :long => "--[no-]bootstrap",
        :description => "Bootstrap the server with knife bootstrap",
        :boolean => true,
        :default => true

      option :ssh_user,
        :short => "-x USERNAME",
        :long => "--ssh-user USERNAME",
        :description => "The user to create and add the provided public key to authorized_keys, default is 'root'",
        :default => "root"

      option :identity_file,
        :short => "-iF IDENTITY_FILE",
        :long => "--identity-file IDENTITY_FILE",
        :description => "The SSH identity file used for authentication",
        :default => "#{File.expand_path('~')}/.ssh/id_rsa"

      option :image_name,
        :short => "-I IMAGE_NAME",
        :long => "--image-name IMAGE_NAME",
        :description => "The image name which will be used to create the server, default is 'Ubuntu-12.04-LTS-server-amd64-06.21.13.img'",
        :default => 'Ubuntu-12.04-LTS-server-amd64-06.21.13.img'

      option :location_name,
        :short => "-loc LOCATION_NAME",
        :long => "--location-name LOCATION_NAME",
        :description => "The Location of the datacenters, default is Karlsruhe 'de/fkb' ",
        :default => 'de/fkb'

      option :snapshot_name,
        :short => '-S SNAPSHOT_NAME',
        :long => "--snaphot-name SNAPSHOT_NAME",
        :description => "The snapshot name which will be used to create the server (can not be used with the image-name option)",
        :proc => Proc.new { |s| Chef::Config[:knife][:profitbricks_snapshot_name] = s }

      option :public_key_file,
        :short => "-k PUBLIC_KEY_FILE",
        :long => "--public-key-file PUBLIC_KEY_FILE",
        :description => "The SSH public key file to be added to the authorized_keys of the given user, default is '~/.ssh/id_rsa.pub'",
        :default => "#{File.expand_path('~')}/.ssh/id_rsa.pub"

      option :run_list,
        :short => "-r RUN_LIST",
        :long => "--run-list RUN_LIST",
        :description => "Comma separated list of roles/recipes to apply",
        :proc => lambda { |o| o.split(/[\s,]+/) },
        :default => []

      option :distro,
        :short => "-d DISTRO",
        :long => "--distro DISTRO",
        :description => "Bootstrap a distro using a template; default is 'ubuntu12.04-gems'",
        :proc => Proc.new { |d| Chef::Config[:knife][:distro] = d },
        :default => "ubuntu12.04-gems"

      option :template_file,
        :long => "--template-file TEMPLATE",
        :description => "Full path to location of template to use",
        :proc => Proc.new { |t| Chef::Config[:knife][:template_file] = t },
        :default => false

      option :chef_node_name,
        :short => "-N NAME",
        :long => "--node-name NAME",
        :description => "The Chef node name for your new node default is the name of the server.",
        :proc => Proc.new { |t| Chef::Config[:knife][:chef_node_name] = t }

      option :ssh_password,
       :short => "-P PASSWORD",
       :long => "--ssh-password PASSWORD",
       :description => "The ssh password to use, default is a random generated one.",
       :proc => Proc.new { |password| Chef::Config[:knife][:ssh_password] = password }

      option :root_password,
       :short => "-rP ROOT_PASSWORD",
       :long => "--root-password PASSWORD",
       :description => "The root ssh password to use for the private Images. The Image should have a root PW",
       :proc => Proc.new { |root_password| Chef::Config[:knife][:root_password] = root_password }


      def h
        @highline ||= HighLine.new
      end

      def run
        validate!
        configure

        #proof for private images
        accepted_formats = acc_formats
        image_extension = image_ext
        if accepted_formats.each {|x| x == image_extension }
          unless Chef::Config[:knife][:root_password]
            ui.error("If you have a private Image, specify also a root password with parameter --root-password PASSWORD!")
            exit 1
          end
        end

        unless Chef::Config[:knife][:profitbricks_datacenter]
          ui.error("A Datacenter must be specified")
          exit 1
        end

        unless Chef::Config[:knife][:profitbricks_lan_id]
          ui.error("A LAN_ID must be specified, to bring the server in a network")
          exit 1
        end

        #unless Chef::Config[:knife][:profitbricks_wan_id]
        #  ui.error("A WAN_ID must be specified, to give the server acces to internet for configuring!")
        #  exit 1
        #end

        unless Chef::Config[:knife][:profitbricks_server_name]
          ui.error("You need to provide a name for the server")
          exit 1
        end

        ui.info "Going to create a new server"
        msg_pair("Name", Chef::Config[:knife][:profitbricks_server_name])
        msg_pair("Datacenter", Chef::Config[:knife][:profitbricks_datacenter])
        msg_pair("Image", Chef::Config[:knife][:profitbricks_image])
        msg_pair("LAN_ID", Chef::Config[:knife][:profitbricks_lan_id])
        #msg_pair("WAN_ID", Chef::Config[:knife][:profitbricks_wan_id])
        msg_pair("Gateway_IP", locate_config_value(:activate_gateway_ip))
        msg_pair("Private_IP", Chef::Config[:knife][:profitbricks_private_ip])
        msg_pair("CPUs", Chef::Config[:knife][:profitbricks_cpus] || 1)
        msg_pair("Memory", Chef::Config[:knife][:profitbricks_memory] || 1024)

        puts "#{ui.color("Locating Datacenter ", :magenta)}"
        @dc = DataCenter.find(:name => Chef::Config[:knife][:profitbricks_datacenter])
        puts "#{ui.color("found dataCenter with Id : #{@dc.id} and Name: #{@dc.name}", :magenta)}"
        @dc.wait_for_provisioning

        # DELETEME for debugging only
        #@dc.clear
        #@dc.wait_for_provisioning
        # DELETEME

        create_server()

        #@password = @new_password
        #change_password()
        #puts ui.color("Changed the password successfully", :green)
        
        #if config[:activate_gateway_ip]
        # activate_gateway()
        #end

        #upload_ssh_key

        if config[:bootstrap]
          bootstrap()
        end

        msg_pair("ID", @server.id)
        msg_pair("Name", @server.name)
        msg_pair("Datacenter", @dc.name)
        msg_pair("CPUs", @server.cores.to_s)
        msg_pair("RAM", @server.ram.to_s)
      end

      def create_server
        @password = SecureRandom.hex.gsub(/[i|l|0|1|I|L]/,'')
        @hdd_name1 = SecureRandom.hex(4)
        @hdd_name2 = SecureRandom.hex(4)

        #locating given image or snapshot
        if locate_config_value(:profitbricks_snapshot_name)
          puts "#{ui.color("Locating Snapshot", :magenta)}"
          @snapshot = Snapshot.find(:name => locate_config_value(:profitbricks_snapshot_name))
        else
          puts "#{ui.color("Locating Image", :magenta)}"  
          @image = Image.find(:name => locate_config_value(:image_name), :location => locate_config_value(:location_name))
          puts "#{ui.color("found Image with Id : #{@image.id} and Name: #{@image.name}", :magenta)}"
        end

          if locate_config_value(:profitbricks_snapshot_name)
            wait_for(ui.color("Creating Storage", :magenta)) { @dc.provisioned? }
            @hdd1 = Storage.create(
                             :size => locate_config_value(:hdd_size),
                             :data_center_id => @dc.id,
                             :name => "HDD-#{@hdd_name1}",
                             :bus_type => 'VIRTIO'
                             )
            @snapshot.update(:bootable => true)
            @snapshot.rollback(:storage_id => @hdd1.id)
            wait_for("#{ui.color("Applying Snapshot", :magenta)}") { @dc.provisioned? }
          elsif locate_config_value(:image_name)
            puts "#{ui.color("will merge HDD with ImageId : #{@image.id} and ImageName: #{@image.name}", :magenta)}"
            accepted_formats = acc_formats
            image_extension = image_ext
            if accepted_formats.each {|x| x == image_extension }
              @hdd1 = Storage.create(:mount_image_id => @image.id,
                                   :size => "8",
                                   :data_center_id => @dc.id,
                                   :name => "HDD-#{@hdd_name1}",
                                   :bus_type => 'VIRTIO'
                                )
              @hdd2 = Storage.create(:size => locate_config_value(:hdd_size),
                                   :data_center_id => @dc.id,
                                   :name => "HDD-#{@hdd_name2}",
                                   :bus_type => 'VIRTIO'
                                )                  
            else
              @hdd1 = Storage.create(:mount_image_id => @image.id,
                                   :profit_bricks_image_password => @password,
                                   :size => locate_config_value(:hdd_size),
                                   :data_center_id => @dc.id,
                                   :name => "HDD-#{@hdd_name1}"
                                )
            end
        end
        #@dc.wait_for_provisioning
        wait_for(ui.color("Creating Storages", :magenta)) { @dc.provisioned? }

        puts "#{ui.color("Start to create the Server ", :magenta)}"
        @server = @dc.create_server(:cores => Chef::Config[:knife][:profitbricks_cpus] || 1,
                                  :ram => Chef::Config[:knife][:profitbricks_memory] || 1024,
                                  :name => Chef::Config[:knife][:profitbricks_server_name] || "ServerNoName",
                                  :boot_from_storage_id => @hdd1.id
                                  )
       
        wait_for(ui.color("Waiting for the Server to be created", :magenta)) { @dc.provisioned? }
        if accepted_formats.each {|x| x == image_ext }
          @hdd2.connect(:server_id => @server.id)
        else
          if locate_config_value(:ssh_password)
           puts "#{ui.color("given password will be applied", :magenta)}"
           @new_password = Chef::Config[:knife][:ssh_password]
           @password = @new_password
           change_password()
          end
        end

        @lan_id_number = Chef::Config[:knife][:profitbricks_lan_id]
        #@wan_id_numer = Chef::Config[:knife][:profitbricks_wan_id]

        #@nic_public = Nic.create(
        #              :lan_id => @wan_id_numer,
        #              :dhcpActive => true,
        #              :name => "RED",
        #              :server_id => @server.id
        #              )

        #@nic_public.set_internet_access = true
        #wait_for("#{ui.color("Connecting public NIC", :magenta)}") { @dc.provisioned? }

        @nic_private = Nic.create(:lan_id => @lan_id_number, 
                       :dhcpActive => locate_config_value(:dhcpActive),
                       :name => "GREEN",
                       :server_id => @server.id,
                       :ip => Chef::Config[:knife][:profitbricks_private_ip])
        
        wait_for("#{ui.color("Connecting private NIC", :magenta)}") { @dc.provisioned? }
        @dc.wait_for_provisioning
        puts "#{ui.color("Done creating new Server #{@server.name}", :green)}"
        @server = Server.find(:id => @server.id)

        wait_for("#{ui.color("Waiting for the Server to boot", :magenta)}") { @server.running? }
        wait_for("#{ui.color("Waiting for the Server with IP: #{@server.private_ips.first} to be accessible", :magenta)}") { ssh_test(@server.private_ips.first) }
        puts "start to connect to ServerIP: #{@server.private_ips.first} with PW #{locate_config_value(:root_password)}"
        #only if we have a private image and the image have lvm
        if accepted_formats.each {|x| x == image_extension }
          #prepare for remote copy of the lvm script
          rP = locate_config_value(:root_password)
          hdSize = locate_config_value(:hdd_size)
          hdSize = (hdSize.to_i - 1)
          remote_ip = @server.public_ips.first
          replacedP = rP.gsub!(/\$/, '\u0024')
          file_to_transfer = `find . -name extendRootPartition.sh | tr -d '\n'`
          ###
          ##assemble the rsync command 
          ###
          #puts "#{file_to_transfer}"
          #rsync_expect_command = "set timeout 20\neval spawn rsync -avz -e \"ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no\" #{file_to_transfer} root@#{remote_ip}:/tmp\nexpect \"*?assword:*\" {send \"#{replaceD}\\r\"}\ninteract"
          #puts "=== #{rsync_expect_command} ==="
          #File.new("rsync.ssh", "w+")
          #File.open("rsync.ssh", "w+") {|file| file.write("#!/usr/bin/expect\n#{rsync_expect_command}")}
          #FileUtils.chmod(0755, 'rsync.ssh') 
          #system ("/bin/bash rsync.ssh")

          puts "#{ui.color("remote test command will be run", :magenta)}"
          ssh_command("ls -alt")
          #upload_ssh_key(rP)
          system ("rsync -avz -e \"ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no\" #{file_to_transfer} root@#{remote_ip}:/tmp")
          upload_file("#{remote_ip}","root","#{file_to_transfer}","/tmp","#{replacedP}")

          #extend root partition with LVM
          ssh_command("chmod +x /tmp/extendRootPartition.sh; /tmp/extendRootPartition.sh /dev/vdb #{hdSize}")
        end
        wait_for(ui.color("Server with Name #{@server.name} and ServerId: #{@server.id} with NIC-IP #{@nic_private.ip} and lan_id #{@lan_id_number} created", :green)) { @dc.provisioned? }
        wait_for(ui.color("Done creating new Server and booting from HDD.Id #{@hdd1.id}", :green)) {@server.provisioned?}

      end

      def upload_file(remoteHost,userName,file,remotePath,passwd)
        # upload a file to a remote server
        puts "will upload #{file} on #{remoteHost} with user #{userName} on #{remotePath} with PW #{passwd} "
        Net::SCP.upload!(remoteHost, userName, file, remotePath, :password => passwd, :paranoid => false, :verbose => :debug)
      end

      def acc_formats
        #proof for private images
        accepted_formats = [".vhd", ".vmdk", ".vdi", ".img", ".iso", ".vpc", ".parallels"]
      return accepted_formats
      end

      def image_ext
        image_ext = File.extname(locate_config_value(:image_name))
      return image_ext
      end 

      def ssh_test(ip)
        begin
          timeout 2 do
            s = TCPSocket.new ip, 22
            s.close
            true
          end
        rescue Timeout::Error, Errno::ECONNREFUSED
          false
        end
      end

      def ssh_command(comm)
        begin
          ssh = Net::SSH.start("#{remote_ip}", :username => 'root', 
            :password => "#{rP}", :paranoid => false, :auth_methods => ['password'], :timeout => 10)
          res = ssh.exec!(comm)
          ssh.close
          puts res
        rescue Timeout::Error, Errno::ECONNREFUSED
          puts "Unable to connect to root@#{remote_ip} with #{rP}"
          exit 2
        end
      end

      def upload_ssh_key(passwd)
        ssh_key = begin
          puts "start the upload of the keys with" 
          outs passwd  
          File.open(locate_config_value(:public_key_file)).read.gsub(/\n/,'')
        rescue Exception => e
          ui.error(e.message)
          ui.error("Could not read the provided public ssh key, check the public_key_file config.")
          exit 1
        end

        dot_ssh_path = if locate_config_value(:ssh_user) != 'root'
          ssh("useradd #{locate_config_value(:ssh_user)} -G sudo -m").run
          "/home/#{locate_config_value(:ssh_user)}/.ssh"
        else
          "/root/.ssh"
        end
        ssh_command("mkdir -p #{dot_ssh_path} && echo \"#{ssh_key}\" > #{dot_ssh_path}/authorized_keys && chmod -R go-rwx #{dot_ssh_path}", "root",passwd)
        puts ui.color("Added the ssh key to the authorized_keys of #{locate_config_value(:ssh_user)}", :green)
      end

      def activate_gateway
        ssh_command("route add default gw #{locate_config_value(:activate_gateway_ip)}", locate_config_value(:root_password))
        puts ui.color("added the gateway route for gateway Server with IP #{locate_config_value(:activate_gateway_ip)}", :green)
      end


      def change_password
        ui.color("start to change the password", :green)
        Net::SSH.start( @server.private_ips.first, 'root', :password =>@password, :paranoid => false ) do |ssh|
          ssh.open_channel do |channel|
             channel.on_request "exit-status" do |channel, data|
                $exit_status = data.read_long
             end
             channel.on_data do |channel, data|
                if data.inspect.include? "current"
                        channel.send_data("#{@password}\n");
                elsif data.inspect.include? "New"
                        channel.send_data("#{@new_password}\n");
                elsif data.inspect.include? "new"
                        channel.send_data("#{@new_password}\n");
                end
             end
             channel.request_pty
             channel.exec("passwd");
             channel.wait

             return $exit_status == 0
          ui.color("password changed successfully", :green)
          end
        end
      end

      def bootstrap
        bootstrap = Chef::Knife::Bootstrap.new
        bootstrap.name_args = @server.ips
        bootstrap.config[:run_list] = locate_config_value(:run_list)
        bootstrap.config[:ssh_user] = locate_config_value(:ssh_user)
        bootstrap.config[:ssh_password] = @password
        bootstrap.config[:host_key_verify] = false
        bootstrap.config[:chef_node_name] = locate_config_value(:chef_node_name) || @server.name
        bootstrap.config[:distro] = locate_config_value(:distro)
        bootstrap.config[:use_sudo] = true unless bootstrap.config[:ssh_user] == 'root'
        bootstrap.config[:template_file] = locate_config_value(:template_file)
        bootstrap.run
        # This is a temporary fix until ohai 6.18.0 is released
        ssh("gem install ohai --pre --no-ri --no-rdoc && chef-client").run
      end
    end
  end
end
