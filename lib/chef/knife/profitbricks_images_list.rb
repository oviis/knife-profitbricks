require 'chef/knife'
require 'chef/json_compat'
require 'pp'

require_relative 'profitbricks_base'
class Chef
  class Knife
    class ProfitbricksImageList < Knife
      require_relative 'profitbricks_base'
      deps do
        require 'profitbricks'
        require 'highline'
        Chef::Knife.load_deps
      end

      include Chef::Knife::ProfitbricksBase

      banner "knife profitbricks image list"

      def run
        configure
        images = Profitbricks::Image.all

        #pp images

        image_list = [
            ui.color('ID', :bold),
            ui.color('Name', :bold),
            ui.color('Memory hotplug', :bold),
            ui.color('CPU hotplug', :bold),
            ui.color('Size', :bold),
            ui.color('Location', :bold),
        ]

        images.each do |i|
          #next if i.type != "HDD"
          image_list << i.id
          image_list << i.name
          image_list << i.ram_hot_plug.to_s
          image_list << i.cpu_hot_plug.to_s
          image_list << i.size.to_s
          image_list << i.location.to_s
        end

        puts ui.list(image_list, :uneven_columns_across, 6)
      end
    end
  end
end
