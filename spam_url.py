from spam_lists import SPAMHAUS_DBL


def check(domain):
    # Check if url is spam or not
    is_spam = domain in SPAMHAUS_DBL
    return not is_spam
