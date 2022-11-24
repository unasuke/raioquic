# frozen_string_literal: true

module Raioquic
  module Quic
    # Raioquic::Quic::Rangeset
    # Migrated from aioquic/src/aioquic/quic/rangeset.py
    class Rangeset
      def initialize(ranges: [])
        @ranges = []
        ranges.each do |r|
          add(r.first, r.last)
        end
        sort
      end

      def list
        @ranges
      end

      def add(start, stop = nil)
        stop = start + 1 if stop.nil?

        @ranges.each_with_index do |r, i|
          # the added range is entirely before current item, insert here
          if stop < r.first
            @ranges.insert(i, (start...stop))
            return # rubocop:disable Lint/NonLocalExitFromIterator
          end

          # the added range is entirely after current item, keep looking
          next if start > r.last

          # the added range touches the current item, merge it
          start = [start, r.first].min
          stop = [stop, r.last].max
          while i < @ranges.size - 1 && @ranges[i + 1].first <= stop
            stop = [@ranges[i + 1].last, stop].max
            @ranges.delete_at(i + 1)
          end
          @ranges[i] = start...stop
          return # rubocop:disable Lint/NonLocalExitFromIterator
        end
        # the added range is entirely after all existing items, append it
        @ranges << (start...stop)
        sort
      end

      def bounds
        @ranges.first&.first...@ranges.last&.last
      end

      def subtract(start, stop) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        raise RuntimeError if stop < start

        i = 0
        while i < @ranges.length
          r = @ranges[i]

          # the removed range is entirely before current item, stop here
          return if stop <= r.first

          # the removed range is entirely after current item, keep looking
          if start >= r.last
            i += 1
            next
          end

          # the removed range completely covers the current item, remove it
          if start <= r.first && stop >= r.last
            @ranges.delete_at(i)
            next
          end

          # the removed range touches the current item
          if start > r.first
            @ranges[i] = r.first...start
            @ranges.insert(i + 1, stop...r.last) if stop < r.last
          else
            @ranges[i] = stop...r.last
          end
          i += 1
        end
        sort
      end

      def shift
        @ranges.shift
      end

      def in?(value)
        @ranges.any? { |r| r.cover?(value) }
      end

      def length
        @ranges.length
      end

      def eql?(other)
        return false if other.class != self.class
        return false if other.length != length

        length.times.all? do |i|
          @ranges[i] == other.list[i]
        end
      end
      alias == eql?

      private def sort
        @ranges.sort! { |a, b| a.first <=> b.first }
      end
    end
  end
end
