import { IPFSAccessController } from '@orbitdb/core';
import { logger } from '@libp2p/logger';

// Create database logger
const dbLog = logger('orbitdb-identity-provider-webauthn-did:database');

/**
 * Opens a TODO database with the given OrbitDB instance and identity
 * @param {Object} orbitdb - The OrbitDB instance
 * @param {Object} identity - The WebAuthn identity
 * @param {Object} identities - The OrbitDB identities instance (unused here)
 * @returns {Object} The opened database instance
 */
export async function openTodoDatabase(orbitdb, identity, identities) {
  // Store references for later use in event handlers
  const ipfsInstance = orbitdb.ipfs;
  const writePermissions = [identity.id];

  console.log('🔓 Database access configuration:', {
    writePermissions,
    identityId: identity.id,
    identityType: identity.type,
  });

  console.log('📝 Opening database "webauthn-todos"...');

  const database = await Promise.race([
    orbitdb.open('webauthn-todos', {
      type: 'keyvalue',
      create: true,
      sync: true,
      accessController: IPFSAccessController({
        write: writePermissions,
      }),
    }),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error('Database open timeout after 15 seconds')),
        15000
      )
    ),
  ]);

  console.log('✅ Database opened successfully:', {
    name: database.name,
    address: database.address,
    type: database.type,
    identityId: database.identity?.id,
    accessControllerType: database.access?.type,
  });

  // Set up database event listeners for debugging
  setupDatabaseEventListeners(database, ipfsInstance, identities);

  return database;
}

/**
 * Sets up event listeners for database debugging
 * @param {Object} database - The database instance
 * @param {Object} ipfs - The IPFS/Helia instance
 * @param {Object} identities - The OrbitDB identities instance
 */
function setupDatabaseEventListeners(database, ipfs, identities) {
  database.events.on('join', (address, entry) => {
    console.log('🔗 Database JOIN event:', { address, entry: entry?.key });
  });

  // Verification happens in the component (shared/lib/verification.js),
  // on every refresh; this listener only logs.
  database.events.on('update', (entry) => {
    console.log('🔄 Database UPDATE event:', {
      hash: entry?.hash,
      identity: entry?.identity,
    });
  });

  database.events.on('error', (error) => {
    console.error('❌ Database ERROR event:', error);
  });
}

/**
 * Loads all todos from the database
 * @param {Object} database - The database instance
 * @returns {Array} Array of todo objects
 */
export async function loadTodos(database) {
  if (!database) return [];

  try {
    console.log('📊 Loading todos from database:', {
      databaseName: database.name,
      databaseAddress: database.address,
      databaseType: database.type,
      identityId: database.identity?.id,
      accessController: database.access?.type,
    });

    console.log('⏳ Calling database.all()...');
    const allTodos = await Promise.race([
      database.all(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('Database.all() timeout after 10 seconds')),
          10000
        )
      ),
    ]);

    console.log('✅ Database.all() completed, entries found:', allTodos.length);

    const todos = allTodos
      .map((entry) => {
        console.log('📝 Todo entry:', { key: entry.key, value: entry.value });
        return entry.value;
      })
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

    console.log('📋 Todos loaded successfully:', todos.length);
    return todos;
  } catch (error) {
    console.error('❌ Failed to load todos:', error);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack?.slice(0, 500),
    });

    // Re-throw the error so the caller can handle it
    throw error;
  }
}

/**
 * Adds a new todo to the database
 * @param {Object} database - The database instance
 * @param {string} text - The todo text
 * @param {Object} credential - The WebAuthn credential (for debugging)
 * @returns {Object} The created todo object
 */
export async function addTodo(database, text, credential = null) {
  if (!database || !text.trim()) {
    throw new Error('Database and todo text are required');
  }

  try {
    const startTime = Date.now();

    const todoId = `todo-${Date.now()}`;
    const todo = {
      id: todoId,
      text: text.trim(),
      completed: false,
      createdAt: new Date().toISOString(),
    };

    dbLog('addTodo() called: %o', { todoId, textLength: text.trim().length });
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null,
    });
    dbLog(
      'Calling database.put() - this will trigger: db.put() → identity.sign() → signIdentity() → webauthnProvider.sign()'
    );

    await database.put(todoId, todo);

    const endTime = Date.now();
    dbLog('database.put() completed in %d ms', endTime - startTime);

    return todo;
  } catch (error) {
    console.error('Failed to add todo:', error);
    throw error;
  }
}

/**
 * Toggles the completed status of a todo
 * @param {Object} database - The database instance
 * @param {Object} todo - The todo object to toggle
 * @returns {Object} The updated todo object
 */
export async function toggleTodo(database, todo) {
  if (!database || !todo) {
    throw new Error('Database and todo are required');
  }

  try {
    const startTime = Date.now();

    const updatedTodo = {
      ...todo,
      completed: !todo.completed,
    };

    dbLog('toggleTodo() called for todo: %s', todo.id);
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null,
    });
    dbLog(
      'Calling database.put() - this will trigger: db.put() → identity.sign() → signIdentity() → webauthnProvider.sign()'
    );

    await database.put(todo.id, updatedTodo);

    const endTime = Date.now();
    dbLog('database.put() completed in %d ms', endTime - startTime);

    return updatedTodo;
  } catch (error) {
    console.error('Failed to toggle todo:', error);
    throw error;
  }
}

/**
 * Deletes a todo from the database
 * @param {Object} database - The database instance
 * @param {Object} todo - The todo object to delete
 */
export async function deleteTodo(database, todo) {
  if (!database || !todo) {
    throw new Error('Database and todo are required');
  }

  try {
    const startTime = Date.now();

    dbLog('deleteTodo() called for todo: %s', todo.id);
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null,
    });
    dbLog(
      'Calling database.del() - this will trigger: db.del() → identity.sign() → signIdentity() → webauthnProvider.sign()'
    );

    await database.del(todo.id);

    const endTime = Date.now();
    dbLog('database.del() completed in %d ms', endTime - startTime);
  } catch (error) {
    dbLog.error('Failed to delete todo: %s', error.message);
    throw error;
  }
}

/**
 * Gets statistics about the todos
 * @param {Array} todos - Array of todo objects
 * @returns {Object} Statistics object
 */
export function getTodoStats(todos) {
  return {
    total: todos.length,
    completed: todos.filter((t) => t.completed).length,
    remaining: todos.filter((t) => !t.completed).length,
  };
}
