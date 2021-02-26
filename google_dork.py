from googlesearch import search


def scan(google_dork):
    # Search Google
    dorks = search(term=google_dork.query,
                   num_results=google_dork.number_of_results, lang=google_dork.lang)
    return dorks