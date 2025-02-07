/**
 * A zero-knowledge proof can prove a statement without revealing any other information about the statement other than
 *  the fact that it is true.
 * 
 * As a learning exercise, we will implement a protocol between Alex who has solved a sudoku and Charlie who wants
 *  to verify that Alex has solved the sudoku, but we don't want Charlie to learn anything about the solution.
 * 
 * The protocol is performed in several rounds, in each round:
 * 1. Alex permutes their solution.
 * 2. Alex commits to their permutation.
 * 3. Charlie asks Alex to reveal one of the following:
 *      - a permuted column
 *      - a permuted row
 *      - a permuted 3x3 box
 *      - the mapping to the original problem
 * 4. Charlie verifies that the revealed information does not violate sudoku rules.
 * 
 * Alex may cheat, but they can not satisfy all of possible requests without knowing the solution.
 * In the worst case for Charlie, Alex may be able to satisfy all but one of the possible requests.
 * 
 * Each round Charlie learns nothing of the solution.
 *   Consider an arbitrarily chosen row   7, 4, _,  3, _, 5,  2, 1, _
 *   and the revealed permutation         6, 3, 7,  8, 9, 2,  4, 5, 1

 * Charlie can learn part of the mapping by inspecting the revealed row e.g. 6 -> 7, 3 -> 4, etc...
 *   but they do not know 7 -> _, or 9 -> _, or 1 -> _
 * 
 * This argument naturally extends to columns and 3x3 boxes too. On the other hand, if Charlie requests the mapping to
 *  be revealed, then they still don't learn anything since the mapping is randomized each round.
 */
import crypto from 'crypto'

// The problem - Alex and Charlie both know this
const _ = 0
const problem = [
    7, 4, _,  3, _, 5,  2, 1, _,
    _, _, _,  7, _, _,  5, 6, _,
    _, _, _,  _, 8, 1,  _, 7, _,

    _, 1, _,  _, 2, 8,  _, _, 7,
    2, _, _,  _, 4, _,  _, _, 6,
    9, _, _,  6, 3, _,  _, 5, _,

    _, 6, _,  8, 5, _,  _, _, _,
    _, 3, 1,  _, _, 2,  _, _, _,
    _, 7, 2,  9, _, 6,  _, 8, 3,
]

// The solution - Only Alex knows this
const solution = [
    7, 4, 8,  3, 6, 5,  2, 1, 9,
    1, 2, 3,  7, 9, 4,  5, 6, 8,
    6, 9, 5,  2, 8, 1,  3, 7, 4,

    3, 1, 6,  5, 2, 8,  9, 4, 7,
    2, 5, 7,  1, 4, 9,  8, 3, 6,
    9, 8, 4,  6, 3, 7,  1, 5, 2,

    4, 6, 9,  8, 5, 3,  7, 2, 1,
    8, 3, 1,  4, 7, 2,  6, 9, 5,
    5, 7, 2,  9, 1, 6,  4, 8, 3,
]

// =====================================================================================================================
function Permute(solution: number[]): Permutation {
    const mapping = shuffle([1, 2, 3, 4, 5, 6, 7, 8, 9])
    const grid = solution.map((x) => mapping[x - 1])

    return { mapping, grid }
}

interface Permutation {
    mapping: number[]       // The mapping of values in the original problem to the new permuted solution
    grid: number[]          // The solution in the new permuted order
}

// =====================================================================================================================
function Commit(permutation: Permutation): Commitment {
    const gridNonces = new Array(permutation.grid.length).fill(0).map(() => crypto.randomInt(2 ** 47))
    const gridHashes = permutation.grid.map((x, i) => hash(x, gridNonces[i]))

    const mappingNonce = crypto.randomInt(2 ** 47)
    const mappingHash = hash(permutation.mapping, mappingNonce)

    return { gridHashes, gridNonces, mappingHash, mappingNonce }
}

interface Commitment {
    gridHashes: Hash[]      // Hash of each number in the permuted solution
    gridNonces: number[]    // The random nonce for each entry in `gridHashes`
    mappingHash: Hash       // Hash of the mapping
    mappingNonce: number    // The random nonce for `mappingHash`
}
type Hash = string

// =====================================================================================================================
function Reveal(permutation: Permutation, commitment: Commitment, request: Request): Response {
    if (request === 'mapping') {
        return {
            type: 'mapping',
            mapping: permutation.mapping,
            nonce: commitment.mappingNonce
        }
    }

    return {
        type: 'values',
        values: request.map(i => permutation.grid[i]),
        nonces: request.map(i => commitment.gridNonces[i]),
    }
}

type Request =
    | number[]      // Indices into the permuted solution
    | 'mapping'     // Mapping to the original problem

type Response =
    | { type: 'mapping', mapping: number[], nonce: number }
    | { type: 'values', values: number[], nonces: number[] }

// =====================================================================================================================
function Verify(request: Request, response: Response, commitment: Commitment): boolean {
    if (request === 'mapping') {
        // Charlie request a mapping, but Alex revealed something else
        if (response.type !== 'mapping') { return false }

        // What Alex revealed did not match the commitment
        if (hash(response.mapping, response.nonce) !== commitment.mappingHash) { return false }

        // The mapping Alex revealed is not a valid mapping (it contains other numbers or duplicate 1..9)
        if (!hasNumbers1To9(response.mapping)) { return false }

        return true
    } else {
        // Charlie request squares to be revealed, but Alex revealed the mapping
        if (response.type === 'mapping') { return false }

        // What Alex revealed did not match the commitment
        for (let i = 0; i < request.length; i++) {
            if (hash(response.values[i], response.nonces[i]) !== commitment.gridHashes[request[i]]) { return false }
        }

        // What Alex revealed violates the rules of Sudoku
        if (!hasNumbers1To9(response.values)) { return false }

        return true
    }
}

// =====================================================================================================================
function Protocol() {
    // At worst, Alex can fake all but one kind of request. So there is a 27/28 chance of fooling Charlie per round.
    // If Charlie repeats this process 5000 times, then Alex only has a 1/2**256 chance of fooling Charlie.
    let rounds = 5000

    for (let i = 0; i < rounds; i++) {
        const permutation = Permute(solution)

        const commitment = Commit(permutation)

        const request = requests[crypto.randomInt(requests.length)]
        const response = Reveal(permutation, commitment, request)

        if (!Verify(request, response, commitment)) {
            return false
        }
    }

    return true
}

// =====================================================================================================================
const requests: Request[] = []

// Rows
for (let y = 0; y < 9; y++) {
    const request = []
    for (let x = y * 9; x < (y + 1) * 9; x++) { request.push(x) }
    requests.push(request)
}

// Columns
for (let x = 0; x < 9; x++) {
    const request = []
    for (let y = x; y < 81; y += 9) { request.push(y) }
    requests.push(request)
}

// Boxes
for (let bx = 0; bx < 3; bx++) {
    for (let by = 0; by < 3; by++) {
        const request = []
        for (let x = bx * 3; x < (bx + 1) * 3; x++) {
            for (let y = by * 3; y < (by + 1) * 3; y++) {
                request.push((y * 9) + x)
            }
        }
        requests.push(request)
    }
}

// Mapping
requests.push('mapping')

// =====================================================================================================================
function hasNumbers1To9(values: number[]): boolean {
    let validation = 0

    for (let i = 0; i < values.length; i++) {
        validation |= (1 << values[i])
    }

    return validation === 0b1111111110
}

function hash(value: number | number[], nonce: number): Hash {
    const h = crypto.createHash('sha256')
    h.update(`${value}:${nonce}`)
    return h.digest('hex')
}

function shuffle<T>(array: T[]): T[] {
    const shuffled = array.slice()
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1))
        const temp = shuffled[i]
        shuffled[i] = shuffled[j]
        shuffled[j] = temp
    }
    return shuffled
}

// =====================================================================================================================
console.log(Protocol())