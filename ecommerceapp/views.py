from django.shortcuts import render, redirect
from ecommerceapp.models import Contact, Product, OrderUpdate, Orders
from django.contrib import messages
from math import ceil
from ecommerceapp import keys
from django.conf import settings
MERCHANT_KEY = keys.MK
import json
from django.views.decorators.csrf import csrf_exempt
from PayTm import Checksum

# Create your views here.
def index(request):
    allProds = []
    catprods = Product.objects.values('category', 'id')
    cats = {item['category'] for item in catprods}
    for cat in cats:
        prod = Product.objects.filter(category=cat)
        n = len(prod)
        nSlides = n // 4 + ceil((n / 4) - (n // 4))
        allProds.append([prod, range(1, nSlides), nSlides])

    params = {'allProds': allProds}
    return render(request, "index.html", params)


def contact(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        desc = request.POST.get("desc")
        pnumber = request.POST.get("pnumber")
        myquery = Contact(name=name, email=email, desc=desc, phonenumber=pnumber)
        myquery.save()
        messages.info(request, "We will get back to you soon.")
        return render(request, "contact.html")
    return render(request, "contact.html")


def about(request):
    return render(request, "about.html")


def checkout(request):
    

    if request.method == "POST":
        items_json = request.POST.get('itemsJson', '')
        name = request.POST.get('name', '')
        amount = request.POST.get('amt')
        email = request.POST.get('email', '')
        address1 = request.POST.get('address1', '')
        address2 = request.POST.get('address2', '')
        city = request.POST.get('city', '')
        state = request.POST.get('state', '')
        zip_code = request.POST.get('zip_code', '')
        phone = request.POST.get('phone', '')
        Order = Orders(items_json=items_json, name=name, amount=amount, email=email, address1=address1, address2=address2, city=city, state=state, zip_code=zip_code, phone=phone)
        Order.save()
        update = OrderUpdate(order_id=Order.order_id, update_desc="The order has been placed")
        update.save()

        # PAYMENT INTEGRATION
        id = Order.order_id
        oid = str(id) + "ShopyCart"
        param_dict = {
            'MID': keys.MID,
            'ORDER_ID': oid,
            'TXN_AMOUNT': str(amount),
            'CUST_ID': email,
            'INDUSTRY_TYPE_ID': 'Retail',
            'WEBSITE': 'WEBSTAGING',
            'CHANNEL_ID': 'WEB',
            'CALLBACK_URL': 'http://127.0.0.1:8000/handlerequest/',
        }
        param_dict['CHECKSUMHASH'] = Checksum.generate_checksum(param_dict, MERCHANT_KEY)
        return render(request, 'paytm.html', {'param_dict': param_dict})

    return render(request, 'checkout.html')


@csrf_exempt
def handlerequest(request):
    form = request.POST
    response_dict = {}
    for i in form.keys():
        response_dict[i] = form[i]
        if i == 'CHECKSUMHASH':
            checksum = form[i]

    verify = Checksum.verify_checksum(response_dict, MERCHANT_KEY, checksum)
    if verify:
        if response_dict['RESPCODE'] == '01':
            print('Order successful')
            a = response_dict['ORDERID']
            b = response_dict['TXNAMOUNT']
            rid = a.replace("ShopyCart", "")

            if rid.isdigit():
                filter2 = Orders.objects.filter(order_id=int(rid))
                for post1 in filter2:
                    post1.oid = a
                    post1.amountpaid = b
                    post1.paymentstatus = "PAID"
                    post1.save()
            else:
                print("Invalid order ID format")
        else:
            print('Order was not successful because ' + response_dict['RESPMSG'])
    return render(request, 'paymentstatus.html', {'response': response_dict})


def profile(request):
   
    
    currentuser = request.user.username
    items = Orders.objects.filter(email=currentuser)
    rid = None
    status = []

    for i in items:
        if i.oid:  # Ensure oid is not None or empty
            rid = i.oid.replace("ShopyCart", "")  # Remove "ShopyCart" from oid
            if not rid.isdigit():  # Check if rid is a valid integer
                rid = None
                continue  # Skip to the next item if rid is invalid
            rid = int(rid)  # Convert rid to an integer
            break  # Use the first valid rid found

    if rid is not None:  # Only query OrderUpdate if rid is valid
        status = OrderUpdate.objects.filter(order_id=rid)
    else:
        messages.warning(request, "No valid orders found.")

    context = {"items": items, "status": status}
    return render(request, "profile.html", context)
