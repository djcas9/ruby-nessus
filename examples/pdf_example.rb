$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

require 'rubygems'
require 'ruby-nessus'
require 'prawn'
require 'prawn/layout'

Prawn::Document.generate("ruby-nessus-example.pdf") do
  self.font_size = 9
  Nessus::XML.new("example.nessus") do |scan|

    footer [margin_box.left, margin_box.bottom + 25] do
      font "Helvetica" do
        stroke_horizontal_rule
        move_down(10)
        text "Ruby-Nessus - http://github.com/mephux/ruby-nessus", :size => 9, :align => :center
      end
    end

    text("#{scan.title}", :size => 20)
    move_down 2
    text("Policy: #{scan.policy_name}")
    text("Policy Description: #{scan.policy_name}")
    text("Runtime: #{scan.runtime}")
    move_down 10

    bounding_box [0,cursor], :width => 490 do
      move_down 10
      data = [["#{scan.host_count}", "#{scan.low_severity_count}", "#{scan.medium_severity_count}", "#{scan.high_severity_count}", "#{scan.open_ports_count}", "#{scan.total_event_count}"]]

      table data,
      :position => :left,
      :border_style => :grid,
      :headers => ['Host Count', 'Low Severity Events', 'Medium Severity Events', 'High Severity Events', 'Open Ports', 'Total Event Count'],
      :align => :left,
      :font_size => 9,
      :row_colors => :pdf_writer,
      :align_headers => :left

      move_down 10
      stroke do
        line bounds.top_left, bounds.top_right
        line bounds.bottom_left, bounds.bottom_right
      end

    end

    scan.hosts do |host|
      move_down(20)

      move_down(10)
      text("#{host.hostname}", :size => 18)
      text("Scan Time: #{host.scan_runtime}")
      text("Low: #{host.low_severity_events} Medium: #{host.medium_severity_events} High: #{host.high_severity_events} Total: #{host.event_count}")
      text("Operating System: #{host.operating_system}")
      move_down 10

      move_down(10)
      @i = 0

      host.events do |event|
        next if event.severity.to_i <= 1
        text("#{@i+=1}. #{event.name}", :size => 11)
        text("\t\t\t- #{event.severity.in_words}")
        text("\t\t\t- #{event.port}")
        move_down(10)
      end

    end
  end
end

puts "PDF Created Successfully!"
