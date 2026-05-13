require 'webrick'

# Suppress WEBrick server signature from error pages (local dev only).
# On GitHub Pages this file is ignored — GH Pages serves 404.html natively.
module WEBrick
  module Config
    HTTP.merge!(ServerSoftware: '', ServerName: '')
  end

  class HTTPResponse
    alias_method :_orig_set_error, :set_error

    def set_error(ex, backtrace = false)
      _orig_set_error(ex, backtrace)
      status = ex.respond_to?(:code) ? ex.code : 500

      # Try to serve the built 404.html from _site
      site_root = ::Jekyll.sites.first&.dest
      custom    = site_root && File.join(site_root, '404.html')

      if status == 404 && custom && File.exist?(custom)
        @header['content-type'] = 'text/html; charset=utf-8'
        @body = File.read(custom)
      else
        @header['content-type'] = 'text/html; charset=utf-8'
        @body = "<!DOCTYPE html><html><head><title>#{status}</title></head>" \
                "<body style='font-family:monospace;padding:4rem;background:#0f0f0f;color:#ccc'>" \
                "<p style='font-size:3rem;color:#fff;margin:0'>#{status}</p>" \
                "<p>page not found.</p><a href='/' style='color:#4ec9b0'>← go home</a>" \
                "</body></html>"
      end
    end
  end
end
