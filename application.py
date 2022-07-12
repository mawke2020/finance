#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import time

from cs50 import SQL

from flask import Flask, flash, redirect, render_template, request, \
    session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, \
    InternalServerError
from werkzeug.security import check_password_hash, \
    generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application

app = Flask(__name__)

# Ensure templates are auto-reloaded

app.config['TEMPLATES_AUTO_RELOAD'] = True


# Ensure responses aren't cached

@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = \
        'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response

# Custom filter

app.jinja_env.filters['usd'] = usd

# Configure session to use filesystem (instead of signed cookies)

app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configure CS50 Library to use SQLite database

db = SQL('sqlite:///finance.db')

# Make sure API key is set

if not os.environ.get('API_KEY'):
    raise RuntimeError('API_KEY not set')


@app.route('/')
@login_required
def index():
    """Show portfolio of stocks"""

    if not session.get('user_id'):
        return redirect(url_for('login'))
    else:
        current_id = session['user_id']
        rows = db.execute('SELECT * FROM users WHERE id = ?',
                          current_id)
        data = \
            db.execute('SELECT * FROM purchase WHERE purchase_id=  ? AND shares <> 0'
                       , current_id)

        balance = rows[0]['cash']

        return render_template('index.html', balance=balance, data=data)


@app.route('/buy', methods=['GET', 'POST'])
@login_required
def buy():
    """Buy shares of stock"""

    current_id = session['user_id']
    rows = db.execute('SELECT * FROM users WHERE id = ?', current_id)
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('fill the symbol field ', 400)
        if lookup(symbol) == None:
            return apology('invalid symbol ', 400)
        shares = request.form.get('shares')
        if not shares:
            return apology('fill the quantity u wanna purchase', 400)
        else:

            data = lookup(symbol)
            name = data['name']
            symbol = data['symbol']
            price = data['price']
            purchase_id = session['user_id']
            total_purchase = float(price) * float(shares)

            balance = float(rows[0]['cash'])
            if float(shares) * float(price) > balance:
                flash(' insuffient amount of money', 'danger')
                return redirect(url_for('buy'))
            else:
                purchase = \
                    db.execute('SELECT * FROM purchase WHERE purchase_id = ?'
                               , purchase_id)
                if not purchase:
                    balance -= float(price) * float(shares)
                    db.execute(
                        'INSERT INTO test (tran_id, symbol ,name, shares, price, total ,time ) VALUES (?,?,?,?,?,?,?)'
                            ,
                        purchase_id,
                        symbol,
                        name,
                        shares,
                        price,
                        total_purchase,
                        time.ctime(),
                        )
                    db.execute(
                        'INSERT INTO purchase (purchase_id, symbol , name ,shares, price ,time ) VALUES (?,?,?,?,?,?)'
                            ,
                        purchase_id,
                        symbol,
                        name,
                        shares,
                        price,
                        time.ctime(),
                        )
                    db.execute(
                        'INSERT INTO transactions (tran_id, symbol ,shares, price ,time ) VALUES (?,?,?,?,?)'
                            ,
                        purchase_id,
                        symbol,
                        shares,
                        price,
                        time.ctime(),
                        )
                    db.execute('UPDATE users SET cash =? WHERE id = ?',
                               balance, current_id)
                    flash('purchased successfully! ', 'success')
                    return redirect(url_for('index'))
                else:

                    symbol_data = \
                        db.execute('SELECT symbol FROM purchase WHERE purchase_id = ?'
                                   , purchase_id)
                    symbol_list = []
                    for i in range(len(symbol_data)):
                        symbol_list.append(symbol_data[i]['symbol'])

                    if request.form.get('symbol') in symbol_list:
                        shares_data = \
                            db.execute('SELECT shares FROM purchase WHERE purchase_id = ? AND symbol = ?'
                                , current_id, symbol)
                        shares_symbol = shares_data[0]['shares']
                        total_shares = int(shares) + int(shares_symbol)
                        price_data = \
                            db.execute('SELECT price FROM purchase WHERE purchase_id = ? AND symbol = ?'
                                , current_id, symbol)
                        price_symbol = float(price_data[0]['price'])
                        prv_total = shares_symbol * price_symbol
                        present_total = float(price) * float(shares)
                        total = prv_total + present_total
                        price = total / total_shares
                        db.execute(
                            'INSERT INTO test (tran_id, symbol ,name, shares, price, total ,time ) VALUES (?,?,?,?,?,?,?)'
                                ,
                            purchase_id,
                            symbol,
                            name,
                            shares,
                            price,
                            total_purchase,
                            time.ctime(),
                            )
                        db.execute(
                            'INSERT INTO transactions (tran_id, symbol ,shares, price ,time ) VALUES (?,?,?,?,?)'
                                ,
                            purchase_id,
                            symbol,
                            shares,
                            price,
                            time.ctime(),
                            )
                        db.execute('UPDATE purchase SET shares = ? , price = ?  WHERE symbol = ? AND purchase_id = ?'
                                   , total_shares, price, symbol,
                                   purchase_id)
                        balance -= float(price) * float(shares)

                        db.execute('UPDATE users SET cash =? WHERE id = ?'
                                   , balance, current_id)
                        flash('purchased successfully!', 'success')
                        return redirect(url_for('index'))
                    else:

                        balance -= float(price) * float(shares)
                        db.execute(
                            'INSERT INTO transactions (tran_id, symbol ,shares, price ,time ) VALUES (?,?,?,?,?)'
                                ,
                            purchase_id,
                            symbol,
                            shares,
                            price,
                            time.ctime(),
                            )
                        db.execute(
                            'INSERT INTO purchase (purchase_id, symbol , name ,shares, price ,time ) VALUES (?,?,?,?,?,?)'
                                ,
                            purchase_id,
                            symbol,
                            name,
                            shares,
                            price,
                            time.ctime(),
                            )
                        db.execute(
                            'INSERT INTO test (tran_id, symbol ,name, shares, price, total ,time ) VALUES (?,?,?,?,?,?,?)'
                                ,
                            purchase_id,
                            symbol,
                            name,
                            shares,
                            price,
                            total_purchase,
                            time.ctime(),
                            )
                        db.execute('UPDATE users SET cash =? WHERE id = ?'
                                   , balance, current_id)
                        flash('purchased successfully!', 'success')
                        return redirect(url_for('index'))
    else:

        return render_template('buy.html')


@app.route('/history')
@login_required
def history():
    """Show history of transactions"""

    current_id = session['user_id']
    data = db.execute('SELECT * FROM transactions WHERE tran_id = ?',
                      current_id)

    return render_template('history.html', data=data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log user in"""

    # Forget any user_id

    session.clear()

    # User reached route via POST (as by submitting a form via POST)

    if request.method == 'POST':

        # Ensure username was submitted

        if not request.form.get('username'):
            return apology('must provide username', 403)
        elif not request.form.get('password'):

        # Ensure password was submitted

            return apology('must provide password', 403)

        # Query database for username

        rows = db.execute('SELECT * FROM users WHERE username = ?',
                          request.form.get('username'))

        # Ensure username exists and password is correct

        if len(rows) != 1 or not check_password_hash(rows[0]['hash'],
                request.form.get('password')):
            return apology('invalid username and/or password', 403)

        # Remember which user has logged in

        session['user_id'] = rows[0]['id']

        # Redirect user to home page

        return redirect('/')
    else:

    # User reached route via GET (as by clicking a link or via redirect)

        return render_template('login.html')


@app.route('/logout')
def logout():
    """Log user out"""

    # Forget any user_id

    session.clear()

    # Redirect user to login form

    return redirect('/')


@app.route('/quote', methods=['GET', 'POST'])
@login_required
def quote():
    """Get stock quote."""

    if request.method == 'POST':
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('please choose symbol', 400)
        if lookup(symbol) == None:
            return apology('invalid symbol please try again', 400)
        else:
            data = lookup(symbol)
            return render_template('quoted.html', data=data)
    else:

        return render_template('quote.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register user"""

    hash_password = ''
    users = db.execute('SELECT username  FROM users')
    user_list = []
    for i in range(len(users)):
        user_list.append(users[i]['username'])

    if request.method == 'POST':
        if not request.form.get('username'):
            return apology('username must be filled', 400)
            flash('username must be filled', 'danger')

        if request.form.get('username') in user_list:
            flash('this user name have been taken choose another one ',
                  'danger')
            return apology('this user name have been taken choose another one '
                           , 400)
        if not request.form.get('password'):
            flash('passowrd must be filled ', 'danger')
            return apology('passowrd must be filled ', 400)
        if not request.form.get('confirmation') \
            == request.form.get('password'):
            flash("password doesn't match", 'danger')
            return apology('password miss-match', 400)
        else:

            hash_password = \
                generate_password_hash(request.form.get('password'))
            db.execute('INSERT INTO users(username,hash) VALUES (?,?)',
                       request.form.get('username'), hash_password)
            flash('Account created!', 'success')
            return redirect(url_for('index'))
    else:

        return render_template('register.html')


        # return apology("TODO")

@app.route('/sell', methods=['GET', 'POST'])
@login_required
def sell():
    """Sell shares of stock"""

    current_id = session['user_id']
    rows = db.execute('SELECT * FROM users WHERE id = ?', current_id)
    symbols = \
        db.execute('SELECT DISTINCT symbol FROM purchase WHERE purchase_id = ? AND shares <> 0'
                   , current_id)

    if request.method == 'POST':
        symbol = request.form.get('symbol')
        qty_shares = \
            db.execute('SELECT shares FROM purchase WHERE purchase_id = ? AND  symbol = ? '
                       , current_id, symbol)
        qty_shares = qty_shares[0]['shares']

        if not symbol:
            return apology(' choose your symbol please', 400)
        if not request.form.get('shares'):
            return apology('please fill the share field', 400)
        if qty_shares < int(request.form.get('shares')):
            return apology(' inssunfient  amount of shares', 400)
        if not request.form.get('shares').isnumeric() \
            or int(request.form.get('shares')) < 0:
            return apology(' inssunfient  amount of shares', 400)
        else:

            data = lookup(symbol)
            price = data['price']
            name = data['name']
            shares_sale = -abs(int(request.form.get('shares')))
            current_shares_symbol = \
                db.execute('SELECT shares FROM purchase WHERE purchase_id = ? AND symbol = ?'
                           , current_id, symbol)
            current_shares_symbol = \
                int(current_shares_symbol[0]['shares'])
            shares = current_shares_symbol \
                - int(request.form.get('shares'))

            balance = float(rows[0]['cash'])
            sale_price = data['price']
            total = float(sale_price) * float(request.form.get('shares'
                    ))
            balance += total
            total_sale = shares_sale * float(sale_price)
            db.execute('UPDATE purchase SET shares = ?  WHERE purchase_id = ? AND symbol = ?'
                       , shares, current_id, symbol)
            db.execute(
                'INSERT INTO transactions (tran_id, symbol ,shares, price ,time ) VALUES (?,?,?,?,?)'
                    ,
                current_id,
                symbol,
                shares_sale,
                price,
                time.ctime(),
                )
            db.execute(
                'INSERT INTO test (tran_id, symbol ,name, shares, price, total ,time ) VALUES (?,?,?,?,?,?,?)'
                    ,
                current_id,
                symbol,
                name,
                shares_sale,
                price,
                total_sale,
                time.ctime(),
                )
            db.execute('UPDATE users SET cash =? WHERE id = ?',
                       balance, current_id)

            flash(' Sale Completed!', 'success')
            return redirect(url_for('index'))
    else:

        return render_template('sale.html', data=symbols)


def errorhandler(e):
    """Handle error"""

    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors

for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
