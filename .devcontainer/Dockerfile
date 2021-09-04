ENV GEM_PATH="/usr/local/rvm/gems/default:/usr/local/rvm/gems/default@global" \
    GEM_HOME="/usr/local/rvm/gems/default" \
    MY_RUBY_HOME="/usr/local/rvm/rubies/default" \
    PATH="/usr/local/rvm/rubies/default/bin:/usr/local/rvm/gems/default@global/bin:/usr/local/rvm/rubies/default/bin:/usr/local/rvm/bin:${PATH}"
COPY library-scripts/ruby-debian.sh /tmp/library-scripts/
RUN apt-get update && bash /tmp/library-scripts/ruby-debian.sh 2.7 automatic true true && rvm use 2.7 && gem install inspec-bin