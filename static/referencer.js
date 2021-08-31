/**
 * **Referencer**
 * Handles references to html elements. Caches all elements with the 'x-r' attribute at start and
 * makes them available to be used in JS. Dumb by design.
 * @example
 * // <p x-r="text" hidden></p>
 * R.preload(); // Preloads the cache
 * R("text").innerText = "Hello world!";
 * R("text").hidden = false;
 * R("foo").hidden = true;
 * // ReferenceError: Referencer: Invalid reference "foo"
 */
const R = (() => {
    const cache = {};
    let preloaded = false;

    // return a function to access the cache
    const f = (identifier) => {
        if (!preloaded) throw "Referencer: References not preloaded.";
        const el = cache[identifier];
        if (el === undefined) throw ReferenceError(`Referencer: Invalid reference "${identifier}"`);
        return cache[identifier];
    };

    // cache populator
    f.preload = async () => {
        if (preloaded) return;
        document.querySelectorAll('[x-r]').forEach(element => {
            cache[element.getAttribute('x-r')] = element;
        })
        preloaded = true;
    }

    return f;
})();