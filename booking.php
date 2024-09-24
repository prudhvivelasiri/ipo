<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flight + Hotel Search | TrailWings</title>
    <link href="https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css" rel="stylesheet">
    <style>
        
       
        header {
            background-color: #4CAF50;
            padding: 30px; /* Increased padding */
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
            box-sizing: border-box;
        }

        .logo {
            color: white;
            font-size: 30px; /* Increased font size */
            font-weight: bold;
            display: flex;
            align-items: center;
        }

        .logo i {
            margin-right: 10px; /* Space between icon and text */
            font-size: 32px; /* Increase icon size */
        }

        .search-container {
            display: flex;
            align-items: center;
            flex-grow: 1;
            margin: 0 20px; /* Add space between logo and search bar */
        }

        .search-container input {
            padding: 10px;
            border-radius: 20px;
            border: none;
            outline: none;
            margin-right: 5px;
            border: 2px solid white;
            width: 100%; /* Full width for input */
            max-width: 300px; /* Limit width for input */
        }

        .search-container button {
            padding: 10px 15px;
            border: none;
            background-color: white;
            color: #4CAF50;
            border-radius: 20px;
            cursor: pointer;
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .nav-links a {
            color: white;
            text-decoration: none;
            font-size: 20px; /* Increased font size for links */
            display: flex;
            align-items: center;
            padding: 10px 15px; /* Add padding to prevent cutoff */
            transition: color 0.3s, transform 0.3s; /* Transition effect */
        }

        .nav-links a i {
            margin-right: 5px;
        }

        .nav-links a:hover {
            color: #f0f8ff; /* Change color on hover */
            transform: scale(1.1); /* Slightly enlarge on hover */
        }

        .profile-container {
            max-width: 1000px;
            margin: 40px auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
        }

        .profile-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }

        .profile-header i {
            font-size: 50px; /* Size of the user icon */
            margin-right: 20px;
            color: #4CAF50; /* Icon color */
        }

        .profile-header h2 {
            margin: 0;
            font-size: 24px;
            color: #333;
        }

        .logo {
            font-size: 28px;
            font-weight: bold;
            display: flex;
            align-items: center;
        }

        .logo i {
            margin-right: 10px;
        }

        .nav-links {
            display: flex;
            gap: 30px;
        }

        .nav-links a {
            color: white;
            text-decoration: none;
            font-size: 16px;
        }

        .nav-links a:hover {
            text-decoration: underline;
        }

        /* Main Booking Section */
        .booking-container {
            background-color: #f0f8ff;
            padding: 100px 20px;
            display: flex;
            justify-content: center;
        }

        .search-bar {
            background-color: white;
            max-width: 1200px;
            width: 100%;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .search-bar form {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }

        .search-bar label {
            margin-bottom: 5px;
            font-size: 14px;
            color: #333;
        }

        .search-bar input,
        .search-bar select {
            padding: 12px;
            font-size: 16px;
            border: 1px solid #ddd;
            border-radius: 5px;
            width: 100%;
        }

        .image-container {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .image-container img {
            width: 30px;
            height: 30px;
            border-radius: 5px;
        }

        /* Full Width for search button */
        .form-full-width {
            grid-column: 1 / 5;
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }

        .search-button button {
            padding: 15px 30px;
            font-size: 18px;
            background-color:  #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .search-button button:hover {
            background-color: #0056b3;
        }

        /* Results Section */
        .results {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 0;
        }

        .results h2 {
            font-size: 24px;
            color: #003580;
            margin-bottom: 20px;
        }

        .results p {
            font-size: 18px;
            color: #333;
        }

        footer {
            background-color: #4CAF50;
            color: white;
            padding:20px;
            text-align: center;
            margin-top: auto;
        }

    </style>
</head>
<body>

<!-- Header -->
<header>
        <div class="logo">
            <i class='bx bxs-plane'></i> <!-- Logo icon -->
            TrailWings
        </div>
        <div class="search-container">
            <input type="text" placeholder="Search...">
            <button type="submit">Search</button>
        </div>
        <div class="nav-links">
            <a href="explore.php">
                <i class='bx bxs-home'></i> Home
            </a>
            <a href="guide.php">
                <i class='bx bxs-compass'></i> Discover
            </a>
            <a href="wishlist.php">
                <i class='bx bxs-heart'></i> Wishlist
            </a>
            <a href="profile.php">
                <i class='bx bxs-user'></i> Profile
            </a>
        </div>
    </header>

<!-- Main Booking Section -->
<section class="booking-container">
    <div class="search-bar">
        <form id="bookingForm">
            <div>
                <label for="departure">Departure Location</label>
                <div class="image-container">
                    <img src="https://via.placeholder.com/30?text=C" alt="Chennai">
                    <input type="text" id="departure" placeholder="Enter departure location" list="departure-locations">
                </div>
                <datalist id="departure-locations">
                    <option value="Chennai">
                    <option value="Bangalore">
                    <option value="Delhi">
                    <option value="Mumbai">
                    <option value="Kolkata">
                </datalist>
            </div>

            <div>
                <label for="destination">Destination Location</label>
                <div class="image-container">
                    <img src="https://via.placeholder.com/30?text=D" alt="Dubai">
                    <input type="text" id="destination" placeholder="Enter destination" list="destination-locations">
                </div>
                <datalist id="destination-locations">
                    <option value="Dubai">
                    <option value="Singapore">
                    <option value="New York">
                    <option value="Tokyo">
                    <option value="London">
                </datalist>
            </div>

            <div>
                <label for="departure-date">Departure Date</label>
                <input type="date" id="departure-date">
            </div>

            <div>
                <label for="return-date">Return Date</label>
                <input type="date" id="return-date">
            </div>

            <div>
                <label for="travellers">Travellers</label>
                <select id="travellers">
                    <option value="1">1 Traveller</option>
                    <option value="2">2 Travellers</option>
                    <option value="3">3 Travellers</option>
                    <option value="4">4 Travellers</option>
                </select>
            </div>

            <div>
                <label for="flight-class">Flight Class</label>
                <select id="flight-class">
                    <option value="economy">Economy</option>
                    <option value="business">Business</option>
                    <option value="first">First Class</option>
                </select>
            </div>

            <div class="form-full-width search-button">
                <button type="submit">Search Flights + Hotels</button>
            </div>
        </form>
    </div>
</section>

<!-- Results Section -->
<section class="results" id="results" style="display: none;">
    <h2>Available Flights and Hotels</h2>
    <p>Here you'll see a list of flights and hotels based on your search.</p>
</section>

<!-- Footer -->
<footer>
    <p>&copy; 2024 TrailWings. All Rights Reserved.</p>
</footer>

<script>
    document.getElementById('bookingForm').addEventListener('submit', function (e) {
        e.preventDefault();
        document.getElementById('results').style.display = 'block';
    });
</script>

</body>
</html>
