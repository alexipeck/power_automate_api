pub fn filter_by_exclusions(strings: Vec<String>, exclusions: Vec<String>) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    'outer: for string in strings.into_iter() {
        for exclusion in exclusions.iter() {
            if string.contains(exclusion) {
                continue 'outer;
            }
        }
        results.push(string);
    }
    results
}
