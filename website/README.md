# MongoDB User Management Console

A web-based GUI application for managing MongoDB built-in users. This console allows you to connect to MongoDB instances and manage authentication users through a modern, intuitive interface.

## Features

- **MongoDB Connection Management**: Connect to MongoDB instances using connection strings
- **User Management**: Create, read, update, and delete MongoDB users
- **Role Management**: Assign and modify user roles
- **Modern UI**: Clean, responsive interface with glassmorphism design
- **Authentication**: Secure login system for console access

## Prerequisites

- Node.js (v14 or higher)
- MongoDB instance (local or remote)
- npm or yarn package manager

## Installation

1. Navigate to the website directory:
   ```bash
   cd website
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the application:
   ```bash
   npm start
   ```

4. Open your browser and navigate to `http://localhost:3000`

## Usage

### 1. Authentication
- First, create an account or login using the authentication section
- You must be authenticated to access MongoDB management features

### 2. Connect to MongoDB
- Navigate to the "MongoDB" section
- Enter your MongoDB connection string (e.g., `mongodb://localhost:27017`)
- Click "Connect" to establish connection
- The status indicator will show connection status

### 3. Manage Users
Once connected, you can:

#### Create Users
- Click "Create User" button
- Fill in username, password, and roles (comma-separated)
- Common roles: `readWrite`, `dbAdmin`, `userAdmin`, `read`, `write`
- Click "Create User" to add the user

#### View Users
- All existing users are displayed in a list
- Shows username, roles, and database information

#### Edit Users
- Click "Edit" button next to any user
- Modify password (optional) and roles
- Click "Update User" to save changes

#### Delete Users
- Click "Delete" button next to any user
- Confirm deletion in the popup dialog

## MongoDB Connection Strings

### Local MongoDB
```
mongodb://localhost:27017
```

### MongoDB with Authentication
```
mongodb://username:password@localhost:27017
```

### MongoDB Atlas (Cloud)
```
mongodb+srv://username:password@cluster.mongodb.net
```

### MongoDB with Specific Database
```
mongodb://localhost:27017/mydatabase
```

## Common MongoDB Roles

- **read**: Read-only access to databases
- **readWrite**: Read and write access to databases
- **dbAdmin**: Administrative access to databases
- **userAdmin**: Manage users and roles
- **clusterAdmin**: Administrative access to the cluster
- **readAnyDatabase**: Read access to all databases
- **readWriteAnyDatabase**: Read/write access to all databases
- **userAdminAnyDatabase**: User management for all databases
- **dbAdminAnyDatabase**: Database administration for all databases

## Security Notes

- This console requires authentication to access MongoDB features
- Connection strings are handled securely
- Users are managed through MongoDB's built-in authentication system
- Always use strong passwords for MongoDB users
- Consider using MongoDB's role-based access control (RBAC) for production environments

## Troubleshooting

### Connection Issues
- Ensure MongoDB is running
- Check connection string format
- Verify network connectivity
- Check firewall settings

### Permission Issues
- Ensure the connecting user has appropriate permissions
- For user management, you need `userAdmin` or `userAdminAnyDatabase` roles
- Some operations require `dbAdmin` or `clusterAdmin` roles

### Common Errors
- **Authentication failed**: Check username/password in connection string
- **Connection refused**: MongoDB service not running
- **Permission denied**: Insufficient user privileges

## API Endpoints

The application provides REST API endpoints for MongoDB management:

- `POST /api/mongo/connect` - Connect to MongoDB
- `POST /api/mongo/disconnect` - Disconnect from MongoDB
- `GET /api/mongo/status` - Check connection status
- `GET /api/mongo/users` - List all users
- `POST /api/mongo/users` - Create new user
- `PUT /api/mongo/users/:username` - Update user
- `DELETE /api/mongo/users/:username` - Delete user

## Development

To modify or extend the application:

1. The backend is in `server.js`
2. Frontend is in `public/index.html` and `public/styles.css`
3. MongoDB operations are handled in the server-side API
4. The UI uses AngularJS for dynamic functionality

## License

This project is part of the Mongo-Schema workspace and follows the same licensing terms.
