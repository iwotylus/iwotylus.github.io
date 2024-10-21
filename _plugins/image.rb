module Jekyll
  module Image
    def add_class_to_images(input, css_class)
      input.gsub(/<img/, "<img class='#{css_class}'")
    end
  end
end

Liquid::Template.register_filter(Jekyll::Image)