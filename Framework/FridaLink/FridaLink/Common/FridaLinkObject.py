#
#  FridaLinkObject.py
#  FridaLink Common  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

class FridaLinkObject(object):
	__propertiesLocked = False
	def __init__(self):
		super(FridaLinkObject, self).__init__()

	def __setattr__(self, key, value):
		if self.__propertiesLocked and not hasattr(self, key):
			raise TypeError( "%r doesn't have property %s" % (self, key) )
		object.__setattr__(self, key, value)
	
	def lockProperties(self):
		self.__propertiesLocked = True
