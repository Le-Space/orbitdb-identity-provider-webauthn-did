/**
 * Todo-Specific Verification (demo app)
 *
 * This module extends the main package's verification utilities with todo-specific logic.
 * The generic verification functions have been moved to the main package.
 *
 * Why: Network-dependent verification (IPFS gateways) is flaky in browsers.
 * This approach guarantees a good UX by verifying using local data only:
 *  - Database ownership (we opened it with our identity)
 *  - Access control (write permissions restrict authors)
 *  - Todo presence and consistency in our local DB
 */

// Import verification utilities from the main package
import { 
  verifyDataEntries, 
  verifyDatabaseUpdate as packageVerifyDatabaseUpdate,
  verifyIdentityStorage as packageVerifyIdentityStorage 
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * Todo-specific match function for data verification
 * @param {Object} todoInDb - Todo object from database
 * @param {Object} expectedTodo - Expected todo object
 * @returns {boolean} True if todos match
 */
function todoMatchFn(todoInDb, expectedTodo) {
  if (!todoInDb || !expectedTodo) return false;
  return todoInDb.id === expectedTodo.id && todoInDb.text === expectedTodo.text;
}

/**
 * Verify todos using the generic package verification utilities
 * @param {Object} database - The OrbitDB database instance
 * @param {Array} todos - Array of todo objects  
 * @param {string} expectedWebAuthnDID - The expected WebAuthn DID
 * @returns {Promise<Map>} Map of todoId -> verification result
 */
export async function verifyTodos(database, todos, expectedWebAuthnDID) {
  console.log(`📝 Using package verification for ${todos.length} todos...`);
  
  // Use the generic verification function from the package with todo-specific matching
  return verifyDataEntries(database, todos, expectedWebAuthnDID, {
    matchFn: todoMatchFn,
    checkLog: true
  });
}

/**
 * Database update verification (delegates to package function)
 * @param {Object} database - The OrbitDB database instance
 * @param {string} identityHash - The identity hash from the update event
 * @param {string} expectedWebAuthnDID - The expected WebAuthn DID
 * @returns {Promise<Object>} Verification result
 */
export async function verifyDatabaseUpdate(database, identityHash, expectedWebAuthnDID) {
  console.log('📝 Using package database update verification...');
  return packageVerifyDatabaseUpdate(database, identityHash, expectedWebAuthnDID);
}

/**
 * Identity storage verification (delegates to package function)
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} identity - The identity object
 * @returns {Promise<Object>} Verification result
 */
export async function verifyIdentityStorage(identities, identity) {
  console.log('📝 Using package identity storage verification...');
  return packageVerifyIdentityStorage(identities, identity);
}

export default {
  verifyTodos,
  verifyDatabaseUpdate,
  verifyIdentityStorage
};
