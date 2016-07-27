## Domain Checker

#Installed pywhois  https://code.google.com/p/pywhois/ for more info
import whois
import csv
import os
import pdb
from dateutil.relativedelta import relativedelta
from datetime import datetime

# Returns an array of useful info on single domain
def queryDomain(domain):
	print 'Determining ownership of ' + domain
	try:
		w = whois.whois(domain)
		daysToExpiration = (w.expiration_date - datetime.now()).days
		print domain + 'is not available. %s days till expiration.' % daysToExpiration
		returnArray = [
			w.domain_name[0],														# Domain Name
			False,																			# availability
			str(datetime.now()), 												# created_at
			w.expiration_date.strftime('%Y-%m-%d') if w.expiration_date else None, 		# expiration_date
			daysToExpiration, 	# Days to Expire
			w.updated_date[0].strftime('%Y-%m-%d'), 		# updated_date
			w.registrar[0], 														# Owner
			]
	except(whois.parser.PywhoisError):
		print(domain) + ' is available.'
		returnArray = [
			domain,																			# Domain Name
			True,																				# availability
			str(datetime.now()), 												# created_at
			None, 		# expiration_date
			None, 	# Days to Expire
			None, 		# updated_date
			None, 														# Owner
			]

	return returnArray


