FROM docker.io/library/ruby:3.1-buster
WORKDIR /src/raioquic
COPY lib/raioquic/version.rb /src/raioquic/lib/raioquic/version.rb
COPY raioquic.gemspec Gemfile Gemfile.lock /src/raioquic
RUN bundle install
COPY . .
