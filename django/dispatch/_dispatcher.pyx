import weakref


def make_id(object target):
    if hasattr(target, '__func__'):
        return id(target.__self__), id(target.__func__)
    return id(target)


NONE_ID = make_id(None)

# A marker for caching
NO_RECEIVERS = object()


def _live_receivers(self, sender):
    """
    Filter sequence of receivers to get resolved, live receivers.

    This checks for weak references and resolves them, then returning only
    live receivers.
    """
    receivers = None
    if self.use_caching and not self._dead_receivers:
        receivers = self.sender_receivers_cache.get(sender)
        # We could end up here with NO_RECEIVERS even if we do check this case in
        # .send() prior to calling _live_receivers() due to concurrent .send() call.
        if receivers is NO_RECEIVERS:
            return []
    if receivers is None:
        with self.lock:
            self._clear_dead_receivers()
            senderkey = make_id(sender)
            receivers = []
            for (receiverkey, r_senderkey), receiver in self.receivers:
                if r_senderkey == NONE_ID or r_senderkey == senderkey:
                    receivers.append(receiver)
            if self.use_caching:
                if not receivers:
                    self.sender_receivers_cache[sender] = NO_RECEIVERS
                else:
                    # Note, we must cache the weakref versions.
                    self.sender_receivers_cache[sender] = receivers
    non_weak_receivers = []
    for receiver in receivers:
        if isinstance(receiver, weakref.ReferenceType):
            # Dereference the weak reference.
            receiver = receiver()
            if receiver is not None:
                non_weak_receivers.append(receiver)
        else:
            non_weak_receivers.append(receiver)
    return non_weak_receivers
