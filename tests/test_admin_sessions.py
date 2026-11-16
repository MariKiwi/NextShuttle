import unittest
from relay.admin_sessions import Sessions
class SessionTests(unittest.TestCase):
    def test_idle_absolute_expiry_capacity_and_restart(self):
        now=[1000];clock=lambda:now[0];sessions=Sessions(clock,capacity=1)
        token,row,ttl=sessions.create(True)
        self.assertNotIn(token,str(sessions.rows));self.assertTrue(sessions.get(token)['authenticated'])
        with self.assertRaises(ValueError):sessions.create()
        self.assertIsNone(Sessions(clock).get(token))
        now[0]+=1801;self.assertIsNone(sessions.get(token))
        token,row,ttl=sessions.create(True)
        for _ in range(29):now[0]+=1000;sessions.get(token)
        self.assertIsNone(sessions.get(token))
    def test_prelogin_is_short_and_duplicate_cookies_are_rejected(self):
        now=[0];sessions=Sessions(lambda:now[0]);token,_,_=sessions.create()
        value=sessions.cookie_name+'='+token
        self.assertEqual(sessions.token(value),token);self.assertEqual(sessions.token(value+'; '+value),'')
        now[0]=301;self.assertIsNone(sessions.get(token))
