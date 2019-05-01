from __future__ import print_function

import argparse
import json
import numpy as np
import matplotlib.pyplot as plt


def mode(x):
    """Returns the mode of the data in X.

       From "https://stackoverflow.com/a/46366383"

       Args:
          x: A list of values.

        Returns:
          The mode of x.
    """
    values, counts = np.unique(x, return_counts=True)
    m = counts.argmax()
    return values[m], counts[m]


def get_category_from_iw_counts(counts):
    """Classifies each server into a category as detailed by Pahdye and Floyd.

       Args:
          counts: A map from initial window sizes to counts (number of trials).

       Returns:
          A map from categories to counts (number of servers).
    """
    non_null_iws = [iw for iw in counts if iw is not None and iw is not 0]
    num_non_null = 5 - (counts[None] if None in counts else 0) - \
                    (counts[0] if 0 in counts else 0)
    if num_non_null >= 3:
        if len(non_null_iws) == 1:
          return 1
        else:
          return 2
    else:
        if len(non_null_iws) == 1:
            return 3
        elif len(non_null_iws) > 1:
            return 4
        else:
            return 5


def get_num_actual_and_bounded_iw_sizes(all_iw_bytes, mss):
    """Estimates the number of actual IW sizes observed.

       Applies the heuristic that if an IW size is evenly divisible
       by the MSS, the congestion window was filled up and therefore
       the IW size is accurate. The remaining observed IW sizes are
       considered lower bounds on the actual IW size.

       Args:
          all_iw_bytes: A list of the IW sizes in bytes for each server.
          mss: The maximum segment size.

       Returns:
          A tuple of the number of actual IW sizes observed and the number
          of IW size lower bounds observed.
    """
    num_actual = 0
    num_lower_bounded = 0
    for iw in all_iw_bytes:
        if iw % mss == 0:
          num_actual += 1
        else:
          num_lower_bounded += 1
    return (num_actual, num_lower_bounded)


def get_category_counts(categories):
    """Counts the number of servers classified in each category.

       Args:
          categories: A map from server to category.

       Returns:
          A map from category to count of servers.
    """
    category_counts = {}
    for ip in categories:
        category = categories[ip]
        if category not in category_counts:
            category_counts[category] = 0
        category_counts[category] += 1
    return category_counts


def plot_iw_cdf(all_iw_bytes, mss):
    """Plots a CDF of the observed IW sizes.

       Args:
          all_iw_bytes: A list of the IW sizes in bytes for each server.
          mss: The maximum segment size.
    """
    num_bins = 20
    counts, bin_edges = np.histogram(all_iw_bytes, bins=num_bins, normed=True)
    cdf = np.cumsum(counts)
    x = bin_edges[1:]
    y = cdf / cdf[-1]
    plt.plot(x, y)
    plt.xlim(min(x), max(x))
    plt.ylim(0.0, 1.0)
    plt.axvline(x=2 * mss, color='red')
    plt.axvline(x=4 * mss, color='red')
    plt.axvline(x=10 * mss, color='red')
    plt.xlabel('Initial window size in bytes (lower bound)')
    plt.ylabel('Cumulative percentage of servers', labelpad=10)
    plt.show()


def parse_log(logfile):
    """Parses LOGFILE and processes the JSON.

       Args:
          logfile: The log file to parse.

        Returns:
          A three-tuple containing the following:
            1) A map from server to category.
            2) A list of all observed initial window sizes in segments.
            3) A list of all observed initial window sizes in bytes.
    """
    categories = {}
    all_iw_segments = []
    all_iw_bytes = []
    with open(logfile, 'r') as f:
        results = json.load(f)
        for ip in results:
            counts = {}
            for iw in results[ip]['Segments']:
                if iw not in counts:
                    counts[iw] = 0
                counts[iw] += 1
            categories[ip] = get_category_from_iw_counts(counts)
            iw = mode(results[ip]['Segments'])[0]
            if iw is not None and iw is not 0:
                all_iw_segments.append(iw)
            iw = mode(results[ip]['Bytes'])[0]
            if iw is not None and iw is not 0:
                all_iw_bytes.append(iw)
    return (categories, all_iw_segments, all_iw_bytes)


def main(args):
    categories, all_iw_segments, all_iw_bytes = parse_log(args.logfile)

    # Table 1
    print('Table 1 results:')
    (num_actual, num_lower_bounded) = \
        get_num_actual_and_bounded_iw_sizes(all_iw_bytes, args.mss)
    print('Number of actual IWs observed: %d' % (num_actual))
    print('Number of IW lower bounds observed: %d' % (num_lower_bounded))
    print('')

    # Table 2
    print('Table 2 results:')
    category_counts = get_category_counts(categories)
    category_numbers = sorted([category for category in category_counts])
    for category in category_numbers:
        print('%d: %d servers' % (category, category_counts[category]))

    # Figure 3
    plot_iw_cdf(all_iw_bytes, args.mss)


if __name__=='__main__':
    parser = argparse.ArgumentParser(
        description='Script to produce results presented in paper.')
    parser.add_argument('-l', '--logfile', type=str, required=True,
                        help='Logfile to generate results from.')
    parser.add_argument('--mss', type=int, required=True,
                        help='The MSS used to produce the logfile.')
    args = parser.parse_args()
    main(args)
