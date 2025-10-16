// Firebase Configuration
const firebaseConfig = {
    apiKey: "your-api-key",
    authDomain: "your-project.firebaseapp.com",
    projectId: "your-project-id",
    storageBucket: "your-project.appspot.com",
    messagingSenderId: "123456789",
    appId: "your-app-id"
};

// Initialize Firebase
try {
    firebase.initializeApp(firebaseConfig);
    console.log('Firebase initialized successfully');
} catch (error) {
    console.error('Firebase initialization error:', error);
}

// Firebase Services
const db = firebase.firestore();
const auth = firebase.auth();

// Firebase Utility Functions
class FirebaseManager {
    constructor() {
        this.isConnected = false;
        this.setupConnectionMonitoring();
    }

    setupConnectionMonitoring() {
        // Monitor connection state
        db.enableNetwork().then(() => {
            this.isConnected = true;
            console.log('Firebase Firestore connected');
        }).catch(error => {
            this.isConnected = false;
            console.error('Firebase Firestore connection failed:', error);
        });

        // Listen for connection state changes
        db.onSnapshot((snapshot) => {
            this.isConnected = true;
        }, (error) => {
            this.isConnected = false;
            console.error('Firebase connection lost:', error);
        });
    }

    async saveScanResult(scanData) {
        if (!this.isConnected) {
            console.warn('Firebase not connected, saving to localStorage only');
            return this.saveToLocalStorage(scanData);
        }

        try {
            const docRef = await db.collection('scanResults').add({
                ...scanData,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                userId: auth.currentUser ? auth.currentUser.uid : 'anonymous'
            });
            return docRef.id;
        } catch (error) {
            console.error('Error saving to Firebase:', error);
            return this.saveToLocalStorage(scanData);
        }
    }

    async getScanHistory(limit = 50) {
        if (!this.isConnected) {
            return this.getFromLocalStorage('scanHistory', limit);
        }

        try {
            const snapshot = await db.collection('scanResults')
                .orderBy('createdAt', 'desc')
                .limit(limit)
                .get();
            
            return snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
        } catch (error) {
            console.error('Error fetching from Firebase:', error);
            return this.getFromLocalStorage('scanHistory', limit);
        }
    }

    async saveCustomQuery(queryData) {
        if (!this.isConnected) {
            return this.saveToLocalStorage('customQueries', queryData, true);
        }

        try {
            const docRef = await db.collection('customQueries').add({
                ...queryData,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
            });
            return docRef.id;
        } catch (error) {
            console.error('Error saving query to Firebase:', error);
            return this.saveToLocalStorage('customQueries', queryData, true);
        }
    }

    saveToLocalStorage(key, data, isArray = false) {
        try {
            if (isArray) {
                const existing = JSON.parse(localStorage.getItem(key)) || [];
                existing.push(data);
                localStorage.setItem(key, JSON.stringify(existing));
            } else {
                localStorage.setItem(key, JSON.stringify(data));
            }
            return true;
        } catch (error) {
            console.error('Error saving to localStorage:', error);
            return false;
        }
    }

    getFromLocalStorage(key, limit = null) {
        try {
            const data = JSON.parse(localStorage.getItem(key)) || [];
            return limit ? data.slice(0, limit) : data;
        } catch (error) {
            console.error('Error reading from localStorage:', error);
            return [];
        }
    }

    // Real-time updates for dashboard
    setupRealTimeUpdates(callback) {
        if (!this.isConnected) return;

        db.collection('scanResults')
            .orderBy('createdAt', 'desc')
            .limit(10)
            .onSnapshot((snapshot) => {
                const updates = snapshot.docChanges();
                updates.forEach(change => {
                    if (change.type === 'added') {
                        callback(change.doc.data());
                    }
                });
            }, (error) => {
                console.error('Real-time updates error:', error);
            });
    }
}

// Initialize Firebase Manager
const firebaseManager = new FirebaseManager();