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
		exp_date = w.expiration_date[0].date()
		daysToExpiration = (exp_date - datetime.now().date()).days
		print domain + 'is not available. %s days till expiration.' % daysToExpiration
		returnArray = [
			w.domain_name[0],														# Domain Name
			False,																			# availability
			str(datetime.now()), 												# created_at
			exp_date if exp_date else None, 		# expiration_date
			daysToExpiration, 	# Days to Expire
#			w.updated_date[0].date(), 		# updated_date
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
#			None, 		# updated_date
			None, 														# Owner
			]

	return returnArray


