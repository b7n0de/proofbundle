# Build-time document date for kramdown-rfc: the template takes Date.today when the source names no date.
require 'date'
class Date
  def self.today
    d = ENV['ID_DATE'] || raise('ID_DATE not set')
    Date.parse(d)
  end
end
