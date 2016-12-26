#
#  ViewStore.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

class ViewStore(object):
    def __init__(self):
        super(ViewStore, self).__init__()
        self.views = []

    def hasView(self, view_id):
        for view in self.views:
            if view is None:
                continue
            if view.view_id == view_id:
                return True
        return False

    def addView(self, title, view):
        insIdx = -1
        for idx, item in enumerate(self.views):
            if item is None:
                insIdx = idx
                break
        if insIdx != -1:
            view.Create(title + "-" + str(insIdx+1))
            self.views[insIdx] = view
        else:
            view.Create(title + "-" + str(len(self.views)+1))
            self.views.append(view)

    def replaceViewId(self, old_id, new_id):
        for idx, view in enumerate(self.views):
            if view is None:
                continue
            if view.view_id == view_id:
                view.view_id = new_id

    def delView(self, view_id):
        for idx, view in enumerate(self.views):
            if view is None:
                continue
            if view.view_id == view_id:
                self.views[idx] = None

    def showView(self, view_id):
        for view in self.views:
            if view is None:
                continue
            if view.view_id == view_id:
                view.Show()
                view.Refresh()
                return

    def setContent(self, view_id, content):
        for view in self.views:
            if view is None:
                continue
            if view.view_id == view_id:
                view.setContent(content)
                return

__all__ = [
    'ViewStore'
]
