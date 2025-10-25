// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyBd65HeQ6ZMKyb8DHc05m9Buj9plk4NY04",
    authDomain: "digital-export-dashboard.firebaseapp.com",
    projectId: "digital-export-dashboard",
    storageBucket: "digital-export-dashboard.firebasestorage.app",
    messagingSenderId: "277722139352",
    appId: "1:277722139352:web:21084a3222f13c0aa1e5ad"
};

// Initialize Firebase
try {
    firebase.initializeApp(firebaseConfig);
    console.log('Firebase initialized successfully');
    
    // Initialize Firestore and Auth
    const db = firebase.firestore();
    const auth = firebase.auth();
    
    // Update Firestore rules to allow your security app to work
    console.log('Firebase services initialized');
    
} catch (error) {
    console.error('Firebase initialization error:', error);
}

// Firebase Manager with updated security rules
class FirebaseManager {
    constructor() {
        this.db = firebase.firestore();
        this.auth = firebase.auth();
        this.isConnected = false;
        this.user = null;
        
        this.setupAuthListener();
        this.setupConnectionMonitoring();
    }

    setupAuthListener() {
        this.auth.onAuthStateChanged((user) => {
            this.user = user;
            if (user) {
                console.log('User signed in:', user.email);
                this.setupUserData(user.uid);
            } else {
                console.log('No user signed in');
                // Use anonymous auth for basic functionality
                this.auth.signInAnonymously().catch(error => {
                    console.log('Anonymous auth not available, using local storage only');
                });
            }
        });
    }

    setupConnectionMonitoring() {
        this.db.enableNetwork().then(() => {
            this.isConnected = true;
            console.log('Firebase Firestore connected');
        }).catch(error => {
            this.isConnected = false;
            console.error('Firebase Firestore connection failed, using local storage:', error);
        });
    }

    async setupUserData(userId) {
        // Initialize user document if it doesn't exist
        const userRef = this.db.collection('users').doc(userId);
        
        try {
            const doc = await userRef.get();
            if (!doc.exists) {
                await userRef.set({
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
                    scanCount: 0
                });
            } else {
                await userRef.update({
                    lastLogin: firebase.firestore.FieldValue.serverTimestamp()
                });
            }
        } catch (error) {
            console.error('Error setting up user data:', error);
        }
    }

    async saveScanResult(scanData) {
        const timestamp = new Date().toISOString();
        const scanId = SecurityUtils.generateReportId();
        
        const enhancedData = {
            ...scanData,
            id: scanId,
            timestamp: timestamp,
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        };

        // Always save to localStorage as fallback
        this.saveToLocalStorage('scanHistory', enhancedData, true);

        // Try to save to Firebase if connected and user is authenticated
        if (this.isConnected && this.user) {
            try {
                const userScanRef = this.db.collection('users').doc(this.user.uid).collection('scans').doc(scanId);
                await userScanRef.set(enhancedData);
                
                // Update user scan count
                const userRef = this.db.collection('users').doc(this.user.uid);
                await userRef.update({
                    scanCount: firebase.firestore.FieldValue.increment(1),
                    lastScan: firebase.firestore.FieldValue.serverTimestamp()
                });
                
                return scanId;
            } catch (error) {
                console.error('Error saving to Firebase:', error);
                return this.saveToLocalStorageOnly(enhancedData);
            }
        } else {
            return this.saveToLocalStorageOnly(enhancedData);
        }
    }

    async getScanHistory(limit = 50) {
        // First try to get from Firebase
        if (this.isConnected && this.user) {
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

                // Merge with local storage
                const localScans = this.getFromLocalStorage('scanHistory', limit);
                const mergedScans = this.mergeScanHistory(firebaseScans, localScans);
                
                return mergedScans.slice(0, limit);
            } catch (error) {
                console.error('Error fetching from Firebase:', error);
            }
        }
        
        // Fallback to local storage
        return this.getFromLocalStorage('scanHistory', limit);
    }

    mergeScanHistory(firebaseScans, localScans) {
        const merged = [...firebaseScans];
        const existingIds = new Set(firebaseScans.map(scan => scan.id));
        
        localScans.forEach(scan => {
            if (!existingIds.has(scan.id)) {
                merged.push(scan);
            }
        });
        
        return merged.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    saveToLocalStorage(key, data, isArray = false) {
        try {
            if (isArray) {
                const existing = JSON.parse(localStorage.getItem(key)) || [];
                const updated = [...existing, data].slice(-100); // Keep last 100
                localStorage.setItem(key, JSON.stringify(updated));
            } else {
                localStorage.setItem(key, JSON.stringify(data));
            }
            return true;
        } catch (error) {
            console.error('Error saving to localStorage:', error);
            return false;
        }
    }

    saveToLocalStorageOnly(scanData) {
        const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
        history.push(scanData);
        localStorage.setItem('scanHistory', JSON.stringify(history.slice(-100)));
        return scanData.id;
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

    // Sync local data to Firebase when connection is restored
    async syncLocalDataToFirebase() {
        if (!this.isConnected || !this.user) return;
        
        try {
            const localScans = this.getFromLocalStorage('scanHistory');
            const batch = this.db.batch();
            
            for (const scan of localScans) {
                const scanRef = this.db.collection('users').doc(this.user.uid).collection('scans').doc(scan.id);
                batch.set(scanRef, scan);
            }
            
            await batch.commit();
            console.log('Local data synced to Firebase');
        } catch (error) {
            console.error('Error syncing local data to Firebase:', error);
        }
    }
}

// Initialize Firebase Manager
const firebaseManager = new FirebaseManager();