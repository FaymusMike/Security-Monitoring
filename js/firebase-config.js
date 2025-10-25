// Firebase Configuration with Proper Error Handling
class FirebaseManager {
    constructor() {
        this.isConnected = false;
        this.user = null;
        this.db = null;
        this.auth = null;
        
        this.initFirebase();
    }

    initFirebase() {
        try {
            const firebaseConfig = {
                apiKey: "AIzaSyBd65HeQ6ZMKyb8DHc05m9Buj9plk4NY04",
                authDomain: "digital-export-dashboard.firebaseapp.com",
                projectId: "digital-export-dashboard",
                storageBucket: "digital-export-dashboard.firebasestorage.app",
                messagingSenderId: "277722139352",
                appId: "1:277722139352:web:21084a3222f13c0aa1e5ad"
            };

            // Initialize Firebase
            if (!firebase.apps.length) {
                firebase.initializeApp(firebaseConfig);
            }
            
            this.db = firebase.firestore();
            this.auth = firebase.auth();
            
            console.log('Firebase initialized successfully');
            this.setupConnectionMonitoring();
            this.setupAuthListener();
            
        } catch (error) {
            console.log('Firebase initialization failed, using local storage only:', error.message);
            this.isConnected = false;
        }
    }

    setupAuthListener() {
        if (!this.auth) return;
        
        this.auth.onAuthStateChanged((user) => {
            this.user = user;
            if (user) {
                console.log('User signed in:', user.uid);
                this.setupUserData(user.uid);
            } else {
                console.log('No user signed in - using local storage');
                // Don't force anonymous auth - it's causing errors
            }
        });
    }

    setupConnectionMonitoring() {
        if (!this.db) return;
        
        this.db.enableNetwork().then(() => {
            this.isConnected = true;
            console.log('Firestore connected');
        }).catch(error => {
            console.log('Firestore offline, using local storage');
            this.isConnected = false;
        });
    }

    async setupUserData(userId) {
        if (!this.db || !this.isConnected) return;
        
        const userRef = this.db.collection('users').doc(userId);
        
        try {
            const doc = await userRef.get();
            if (!doc.exists) {
                await userRef.set({
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
                    scanCount: 0
                });
            }
        } catch (error) {
            console.error('Error setting up user data:', error);
        }
    }

    async saveScanResult(scanData) {
        const timestamp = new Date().toISOString();
        const scanId = 'scan-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        
        const enhancedData = {
            ...scanData,
            id: scanId,
            timestamp: timestamp
        };

        // Always save to localStorage first
        const localId = this.saveToLocalStorage(enhancedData);

        // Try to save to Firebase if connected
        if (this.isConnected && this.db && this.user) {
            try {
                const userScanRef = this.db.collection('users').doc(this.user.uid).collection('scans').doc(scanId);
                await userScanRef.set({
                    ...enhancedData,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp()
                });
                
                console.log('Scan saved to Firebase');
                return scanId;
            } catch (error) {
                console.error('Error saving to Firebase:', error);
                return localId;
            }
        }
        
        return localId;
    }

    async getScanHistory(limit = 50) {
        // Try Firebase first if available
        if (this.isConnected && this.db && this.user) {
            try {
                const snapshot = await this.db.collection('users')
                    .doc(this.user.uid)
                    .collection('scans')
                    .orderBy('timestamp', 'desc')
                    .limit(limit)
                    .get();
                
                const firebaseScans = snapshot.docs.map(doc => ({
                    id: doc.id,
                    ...doc.data()
                }));

                return firebaseScans;
            } catch (error) {
                console.error('Error fetching from Firebase:', error);
            }
        }
        
        // Fallback to local storage
        return this.getFromLocalStorage(limit);
    }

    saveToLocalStorage(scanData) {
        try {
            const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
            history.push(scanData);
            
            // Keep only last 100 entries
            const updatedHistory = history.slice(-100);
            localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
            
            return scanData.id;
        } catch (error) {
            console.error('Error saving to localStorage:', error);
            return 'local-' + Date.now();
        }
    }

    getFromLocalStorage(limit = null) {
        try {
            const data = JSON.parse(localStorage.getItem('scanHistory')) || [];
            return limit ? data.slice(-limit) : data;
        } catch (error) {
            console.error('Error reading from localStorage:', error);
            return [];
        }
    }
}

// Initialize Firebase Manager
const firebaseManager = new FirebaseManager();