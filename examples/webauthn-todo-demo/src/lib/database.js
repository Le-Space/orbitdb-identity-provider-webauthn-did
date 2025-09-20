import { IPFSAccessController } from '@orbitdb/core';

/**
 * Opens a TODO database with the given OrbitDB instance and identity
 * @param {Object} orbitdb - The OrbitDB instance
 * @param {Object} identity - The WebAuthn identity
 * @returns {Object} The opened database instance
 */
export async function openTodoDatabase(orbitdb, identity) {
  const writePermissions = [identity.id];
  
  console.log('🔓 Database access configuration:', {
    writePermissions,
    identityId: identity.id,
    identityType: identity.type
  });
  
  console.log('📝 Opening database "webauthn-todos"...');
  
  const database = await Promise.race([
    orbitdb.open('webauthn-todos', {
      type: 'keyvalue',
      create: true,
      sync: true,
      accessController: IPFSAccessController({ 
        write: writePermissions
      })
    }),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Database open timeout after 15 seconds')), 15000)
    )
  ]);
  
  console.log('✅ Database opened successfully:', {
    name: database.name,
    address: database.address,
    type: database.type,
    identityId: database.identity?.id,
    accessControllerType: database.access?.type
  });
  
  // Set up database event listeners for debugging
  setupDatabaseEventListeners(database);
  
  return database;
}

/**
 * Sets up event listeners for database debugging
 * @param {Object} database - The database instance
 */
function setupDatabaseEventListeners(database) {
  database.events.on('join', (address, entry) => {
    console.log('🔗 Database JOIN event:', { address, entry: entry?.key });
  });
  
  database.events.on('update', (address) => {
    console.log('🔄 Database UPDATE event:', { address });
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
      accessController: database.access?.type
    });
    
    console.log('⏳ Calling database.all()...');
    const allTodos = await Promise.race([
      database.all(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Database.all() timeout after 10 seconds')), 10000)
      )
    ]);
    
    console.log('✅ Database.all() completed, entries found:', allTodos.length);
    
    const todos = allTodos
      .map(entry => {
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
      stack: error.stack?.slice(0, 500)
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
    // 🧪 DEBUG: Test direct WebAuthn call before OrbitDB operation
    if (credential) {
      console.log('🧪 [DEBUG] Testing direct WebAuthn call before adding TODO...');
      try {
        const testChallenge = crypto.getRandomValues(new Uint8Array(32));
        console.log('🧪 [DEBUG] Calling navigator.credentials.get directly - this should show biometric prompt!');
        
        const directAuth = await navigator.credentials.get({
          publicKey: {
            challenge: testChallenge,
            allowCredentials: [{
              id: credential.rawCredentialId,
              type: 'public-key'
            }],
            userVerification: 'required',
            timeout: 60000
          }
        });
        
        console.log('🧪 [DEBUG] Direct WebAuthn auth successful:', {
          hasResponse: !!directAuth?.response,
          hasAuthenticatorData: !!directAuth?.response?.authenticatorData
        });
      } catch (directAuthError) {
        console.warn('🧪 [DEBUG] Direct WebAuthn auth failed:', directAuthError.message);
      }
    }
    
    const todoId = `todo-${Date.now()}`;
    const todo = {
      id: todoId,
      text: text.trim(),
      completed: false,
      createdAt: new Date().toISOString()
    };
    
    console.log('🧪 [DEBUG] Now calling OrbitDB database.put() - this should also trigger biometric prompt...');
    await database.put(todoId, todo);
    
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
    const updatedTodo = {
      ...todo,
      completed: !todo.completed
    };
    
    await database.put(todo.id, updatedTodo);
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
    await database.del(todo.id);
  } catch (error) {
    console.error('Failed to delete todo:', error);
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
    completed: todos.filter(t => t.completed).length,
    remaining: todos.filter(t => !t.completed).length
  };
}