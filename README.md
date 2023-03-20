# Raioquic

Raioquic is a ruby porting of [aiortc/aioquic](https://github.com/aiortc/aioquic), that python's async IO library.

## :warning: **DISCLAIMER** :warning:

Porting is incomplete, and I'm not going to create complete porting. Do not use this gem in production. If you want to use this gem, you **SHOULD** deeply understand QUIC protocol.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'raioquic'
```

And then execute:

```sh
$ bundle install
```

Or install it yourself as:

```sh
$ gem install raioquic
```

## Usage

See [test](test/) and [example/](example/).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/unasuke/raioquic. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/unasuke/raioquic/blob/main/CODE_OF_CONDUCT.md).

## Code of Conduct

Everyone interacting in the Raioquic project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/unasuke/raioquic/blob/main/CODE_OF_CONDUCT.md).

## Acknowledgement
* <https://github.com/aiortc/aioquic>
