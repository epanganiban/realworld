import { applyMiddleware, createStore, combineReducers } from 'redux';
import { promiseMiddleware } from './middleware';
import auth from './reducers/auth';
import common from './reducers/common';
import home from './reducers/home';

const defaultState = {
  appName: 'conduit',
  articles: null
};

const reducer = combineReducers({
  auth,
  common,
  home
});
const middleware = applyMiddleware(promiseMiddleware);
const store = createStore(reducer, middleware);

export default store;