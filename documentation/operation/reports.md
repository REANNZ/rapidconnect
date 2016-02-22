# Instructions for querying registrations present in Rapid Connect

## Initiate a console
Within the RapidConnect application environment you have setup:

    $> rbenv exec bundle exec irb -I. -rinit


## Query Data

    irb(main)> redis = Redis.new
    irb(main)> redis.hgetall('serviceproviders').values.map { |v| JSON.parse(v) }.select { |s| s['enabled'] }.map { |s| [Time.at(s['created_at'] || 0).to_date.iso8601, s['name'], s['organisation'], s['audience']] }.sort { |a, b| a[0] <=> b[0] }.each { |row| puts row.join(',') }; true

## Output
The response will be in the form:

    created_at | name | organisation | audience

Enjoy!
