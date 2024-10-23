module Jekyll
  module AddHeaderClass
    def add_class_to_headings(input, css_class = 'blog-header')
      # Use gsub to find and replace h2-h6 tags, adding the class
      input.gsub(/<(h[2-6])(.*?)>/, "<\\1 class='#{css_class}' \\2>")
    end
  end
end

# Register the filter in Liquid
Liquid::Template.register_filter(Jekyll::AddHeaderClass)