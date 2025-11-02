🛍️ Sales Insight Dashboard

A comprehensive full-stack web application for managing retail sales, inventory, and customer analytics, built entirely in Python with Streamlit.

🎯 Project Overview

The Sales Insight Dashboard is a complete solution for managing retail operations. It provides a secure, multi-user platform for managing products, customers, and sales, all while offering advanced analytics, machine learning-powered sales forecasts, and automated customer segmentation.

It features a clean, responsive interface with real-time dashboards, interactive Plotly charts, and comprehensive data management capabilities.

✨ Key Features

🔐 Secure Authentication & RBAC: Full user login system with secure PBKDF2 password hashing and role-based access control (Super Admin, Manager, Sales Associate, Viewer).

📊 Interactive Dashboard: Real-time KPIs, sales trends, top products, and customer demographics, all visualized with interactive Plotly charts.

📝 Comprehensive Data Management: Full CRUD (Create, Read, Update, Delete) interface for managing Products, Customers, and Sales records.

📦 Automated Inventory Control: Sales records automatically update product stock levels in real-time.

🔮 ML Sales Forecasting: Uses scikit-learn (Linear & Polynomial Regression) to generate future sales forecasts with selectable confidence intervals.

🚀 Inventory Velocity Analysis: Automatically analyzes sales velocity to provide concrete reorder recommendations (e.g., "URGENT: Stockout in 7 days").

🎯 RFM Customer Segmentation: Performs Recency, Frequency, and Monetary (RFM) analysis to automatically segment customers ("Champions," "At Risk," etc.) and provides actionable marketing strategies for each segment.

⚙️ Admin & Backup System: Secure panel for user management, one-click database backups, and full database restoration from a backup file.

📤 Data Export: Allows users to generate and download filtered reports for Sales, Products, and Customers as CSV files.

🏗️ Architecture

Application (Streamlit)

Framework: Streamlit serves as both the backend server and the frontend rendering engine.

Backend Logic: Python handles all business logic, database interactions, and user authentication.

Data Analytics: Pandas and NumPy are used for all data manipulation and analysis.

Machine Learning: scikit-learn and SciPy power the sales forecasting and statistical analysis.

Visualizations: Plotly is used for all interactive charts and graphs.

Database (SQLite)

Database: A single-file SQLite database (database.db) is used for all data persistence.

Schema: The database is automatically initialized on first run by app.py.

Database Schema

users: Stores user accounts, hashed passwords, and role_id.

roles: Defines the user roles (e.g., "Super Admin", "Manager").

permissions: Defines available permissions (e.g., "manage_users", "view_reports").

role_permissions: Maps roles to their assigned permissions.

user_sessions: Manages active user login sessions with secure tokens.

products: Stores all product information, including name, category, price, and stock.

customers: Stores all customer details, including name, email, and demographics.

sales: Stores all transaction records, linked via foreign keys to products and customers.

🚀 Zero-Error Setup Guide (Replit)

This application is designed to run perfectly on Replit with zero configuration.

Repository: Ensure all files (app.py, .replit, pyproject.toml) are in the Replit environment.

Dependencies: Dependencies are listed in pyproject.toml and will be installed automatically by Replit.

Run the Application:

Simply press the "Run" button at the top of the Replit interface.

The .replit file is configured to launch the Streamlit app on port 5000 and make it available in the webview.

Access the Application:

The application will load in the "Web" tab.

Log in using the default administrator credentials:

Username: admin

Password: admin123

The database (database.db) will be created and populated with demo data on the very first run.

📚 How to Use

📊 Dashboard

View high-level KPIs for sales, revenue, and customers.

Interact with charts: zoom, pan, and hover to see detailed data.

Use the date and category filters to narrow down the analytics.

📝 Manage Data

Navigate to the "Manage Data" section from the sidebar.

Use the tabs (Products, Customers, Sales) to manage data.

Add New Item: Expand the "Add New..." section, fill the form, and submit.

Edit/Delete Item: Find the item in the list, expand it, and click "Edit" or "Delete".

Note: Deleting a sale automatically restores the stock count to the product. Adding a sale automatically reduces it.

🔮 Forecasting

Go to the "Forecasting" page.

Select a forecast period (e.g., 30 days), model type, and confidence level.

View the generated forecast chart and model performance metrics (R² score).

Review the "Automated Reorder Recommendations" to see which products need immediate attention.

👥 Customer Segments

Go to the "Customer Segments" page.

The system will automatically run RFM analysis and display the customer portfolio overview.

Review the "Customer Segment Breakdown" pie chart and statistics table.

Expand the "Marketing Strategy Recommendations" tabs (High, Medium, Low Priority) to see actionable advice for each segment.

⚙️ Settings (Admin Panel)

Navigate to "Settings".

User Management: As an Admin, you can navigate to "User Management" to create, edit, or delete users.

Change Password: Any user can change their own password in the "User Profile" section.

Backup & Restore (Admin only):

Create Backup: Go to the "Backup & Restore" section and click "Create Full Backup".

Restore: Select a backup file from the list, check the confirmation box, and click "Restore Database". A backup of the current state is automatically made first.

Download/Delete: You can download or delete any existing backup.

🚦 Status Indicators (Inventory)

The "Forecasting" page provides clear, color-coded status alerts for inventory:

🔴 URGENT: Product will run out in < 7 days. High priority.

🟡 WARNING: Product will run out in 7-14 days. Medium priority.

ℹ️ SLOW MOVER: Product has sufficient stock but no recent sales.

🔍 Troubleshooting

"No data available" on dashboard: The database might be empty. Go to Manage Data and add some products, customers, and sales to see the charts populate. The initial run should populate demo data.

Permission Error: If you see a permission error, your assigned role (e.g., "Viewer") does not have access to that feature. Log in as an admin for full access.

Forecast Error: The "Insufficient historical data" warning appears if there are fewer than 7 days of sales. Add more sales records to enable forecasting.

📄 License

This project is open-source and available for use and modification.
