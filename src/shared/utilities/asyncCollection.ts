/*!
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import { Coalesce } from './tsUtils'

/**
 * High-level abstraction over async generator functions of the form `async function*` {@link AsyncGenerator}
 */
export interface AsyncCollection<T> extends AsyncIterable<T> {
    /**
     * Flattens the collection 1-level deep.
     */
    flatten(): AsyncCollection<SafeUnboxIterable<T>>

    /**
     * Applies a mapping transform to the output generator.
     */
    map<U>(fn: (obj: T) => Promise<U> | U): AsyncCollection<U>

    unorderedMap<U>(fn: (obj: T) => Promise<U>): AsyncCollection<U>

    /**
     * Filters out results which will _not_ be passed on to further transformations.
     */
    filter<U extends T>(predicate: (item: T) => item is U): AsyncCollection<U>
    filter<U extends T>(predicate: (item: T) => boolean): AsyncCollection<U>

    find<U extends T>(predicate: (item: T) => item is U): Promise<U | undefined>
    find<U extends T>(predicate: (item: T) => boolean): Promise<U | undefined>

    /**
     * Uses only the first 'count' number of values returned by the generator.
     */
    limit(count: number): AsyncCollection<T>

    /**
     * Converts the collection to a Promise, resolving to an array of all values returned by the generator.
     */
    promise(): Promise<T[]>

    /**
     * Converts the collection to a Map, using either a property of the item or a function to select keys
     */
    toMap<K extends StringProperty<T>, U extends string = never>(
        selector: KeySelector<T, U> | K
    ): Promise<Map<Coalesce<U, T[K]>, T>>

    /**
     * Returns an iterator directly from the underlying generator, preserving values returned.
     */
    iterator(): AsyncIterator<T, T | void>
}

const asyncCollection = Symbol('asyncCollection')

/**
 * Converts an async generator function to an {@link AsyncCollection}
 *
 * Generation is "lazy", i.e. the generator is not called until a resolving operation:
 *  * Iterating over them using `for await (...)`
 *  * Iterating over them using `.next()`
 *  * Calling one of the conversion functions `toMap` or `promise`
 *
 * Collections are *immutable* in the sense that any transformation will not consume the underlying generator
 * function. That is, any 'final' operation uses its own contextually bound generator function separate from
 * any predecessor collections.
 */
export function toCollection<T>(generator: () => AsyncGenerator<T, T | undefined | void>): AsyncCollection<T> {
    async function* unboxIter() {
        const last = yield* generator()
        if (last !== undefined) {
            yield last
        }
    }

    const iterable: AsyncIterable<T> = {
        [Symbol.asyncIterator]: unboxIter,
    }

    return Object.assign(iterable, {
        [asyncCollection]: true,
        find: <U extends T>(predicate: Predicate<T, U>) => find(iterable, predicate),
        flatten: () => toCollection<SafeUnboxIterable<T>>(() => delegateGenerator(generator(), flatten)),
        filter: <U extends T>(predicate: Predicate<T, U>) =>
            toCollection<U>(() => filterGenerator<T, U>(generator(), predicate)),
        map: <U>(fn: (item: T) => Promise<U> | U) => toCollection<U>(() => mapGenerator(generator(), fn)),
        unorderedMap: <U>(fn: (obj: T) => Promise<U>) => toCollection<U>(() => unorderedMap(generator(), fn)),
        limit: (count: number) => toCollection(() => delegateGenerator(generator(), takeFrom(count))),
        promise: () => promise(iterable),
        toMap: <U extends string = never, K extends StringProperty<T> = never>(selector: KeySelector<T, U> | K) =>
            asyncIterableToMap(iterable, selector),
        iterator: generator,
    })
}

export function isAsyncCollection<T>(iterable: AsyncIterable<T>): iterable is AsyncCollection<T> {
    return asyncCollection in iterable
}

async function* mapGenerator<T, U, R = T>(
    generator: AsyncGenerator<T, R | undefined | void>,
    fn: (item: T | R) => Promise<U> | U
): AsyncGenerator<U, U | undefined> {
    while (true) {
        const { value, done } = await generator.next()
        if (done) {
            return value !== undefined ? (fn(value) as Awaited<U>) : undefined
        }
        if (value !== undefined) {
            yield fn(value)
        }
    }
}

type Predicate<T, U extends T> = (item: T) => item is U

async function* filterGenerator<T, U extends T, R = T>(
    generator: AsyncGenerator<T, R | undefined | void>,
    predicate: Predicate<T | R, U> | ((item: T | R) => boolean)
): AsyncGenerator<U, U | void> {
    while (true) {
        const { value, done } = await generator.next()

        if (done) {
            if (value !== undefined && predicate(value)) {
                return value as unknown as Awaited<U>
            }
            break
        }

        if (predicate(value)) {
            yield value
        }
    }
}

async function* delegateGenerator<T, U, R = T>(
    generator: AsyncGenerator<T, R | undefined | void>,
    fn: (item: T | R, ret: () => void) => AsyncGenerator<U, void>
): AsyncGenerator<U, U | undefined> {
    type LastValue = Readonly<{ isSet: false; value?: undefined } | { isSet: true; value: Awaited<U> }>
    let last: LastValue = { isSet: false }

    while (true) {
        const { value, done } = await generator.next()
        if (value !== undefined) {
            const delegate = fn(value, generator.return.bind(generator))
            while (true) {
                const sub = await delegate.next()
                if (sub.done) {
                    break
                }
                if (last.isSet) {
                    yield last.value
                }
                last = { isSet: true, value: sub.value as Awaited<U> }
            }
        }
        if (done) {
            break
        }
    }

    // The last value is buffered by one step to ensure it is returned here
    // rather than yielded in the while loops.
    return last.value
}

async function* flatten<T, U extends SafeUnboxIterable<T>>(item: T) {
    if (isIterable<U>(item)) {
        yield* item
    } else {
        yield item as unknown as U
    }
}

function takeFrom<T>(count: number) {
    return async function* (item: T, ret: () => void) {
        if (--count < 0) {
            return ret()
        }
        yield item
    }
}

/**
 * Either 'unbox' an Iterable value or leave it as-is if it's not an Iterable
 */
type SafeUnboxIterable<T> = T extends Iterable<infer U> ? U : T

export function isIterable<T>(obj: any): obj is Iterable<T> {
    return obj !== undefined && typeof obj[Symbol.iterator] === 'function'
}

async function promise<T>(iterable: AsyncIterable<T>): Promise<T[]> {
    const result: T[] = []

    for await (const item of iterable) {
        result.push(item)
    }

    return result
}

function addToMap<T, U extends string>(map: Map<string, T>, selector: KeySelector<T, U> | StringProperty<T>, item: T) {
    const key = typeof selector === 'function' ? selector(item) : item[selector]
    if (key) {
        if (map.has(key as keyof typeof map['keys'])) {
            throw new Error(`Duplicate key found when converting AsyncIterable to map: ${key}`)
        }

        map.set(key as keyof typeof map['keys'], item)
    }
}

// Type 'U' is constrained to be either a key of 'T' or a string returned by a function parsing 'T'
type KeySelector<T, U extends string> = (item: T) => U | undefined
type StringProperty<T> = { [P in keyof T]: T[P] extends string ? P : never }[keyof T]

// TODO: apply this to different iterables and replace the old 'map' code
async function asyncIterableToMap<T, K extends StringProperty<T>, U extends string = never>(
    iterable: AsyncIterable<T>,
    selector: KeySelector<T, U> | K
): Promise<Map<Coalesce<U, T[K]>, T>> {
    const result = new Map<Coalesce<U, T[K] & string>, T>()

    for await (const item of iterable) {
        addToMap(result, selector, item)
    }

    return result
}

async function find<T, U extends T>(iterable: AsyncIterable<T>, predicate: (item: T) => item is U) {
    for await (const item of iterable) {
        if (predicate(item)) {
            return item
        }
    }
}

async function* unorderedMap<T, U, R = T>(
    generator: AsyncGenerator<T, R | undefined | void>,
    fn: (item: T | R) => Promise<U>
): AsyncGenerator<U, U | void> {
    type Next = { readonly type: 'next'; readonly data: IteratorResult<T, R | undefined | void> }
    type Pending = { readonly type: 'pending'; readonly data: U; readonly index: number }

    const unresolved = new Map<number, Promise<Pending>>()
    let count = 0
    let isGeneratorDone = false
    let isReturnValue = false
    let nextValue: Promise<Next> | undefined

    function next(): Promise<Next | Pending> {
        if (isGeneratorDone) {
            return Promise.race(unresolved.values())
        }

        nextValue ??= generator
            .next()
            .then(data => ({ type: 'next' as const, data }))
            .finally(() => (nextValue = undefined))

        if (unresolved.size === 0) {
            return nextValue
        }

        const pending = Promise.race(unresolved.values())
        return Promise.race([nextValue, pending])
    }

    function addPending(val: T | R) {
        const index = count++
        unresolved.set(
            index,
            fn(val).then(data => ({ type: 'pending' as const, data, index }))
        )
    }

    while (!isGeneratorDone || unresolved.size > 0) {
        const nextVal = await next()
        if (nextVal.type === 'pending') {
            unresolved.delete(nextVal.index)
            if (isReturnValue && unresolved.size === 0) {
                return nextVal.data
            }
            yield nextVal.data
        } else if (nextVal.type === 'next') {
            const { value, done } = nextVal.data
            if (!done) {
                addPending(value)
            } else {
                isGeneratorDone = true

                if (value !== undefined) {
                    isReturnValue = true
                    addPending(value)
                }
            }
        }
    }
}
